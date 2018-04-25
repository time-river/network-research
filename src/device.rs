/* https://github.com/polachok/tuntap/blob/master/src/lib.rs */

use std::{cmp, ffi, fs, io, mem, process};
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};

use libc;
use libc::{c_char, c_short, c_int, c_ulong};

pub trait IsMinusOne {
    fn is_minus_one(&self) -> bool;
}

macro_rules! impl_is_minus_one {
    ($($t:ident)*) => ($(impl IsMinusOne for $t {
        fn is_minus_one(&self) -> bool {
            *self == -1
        }
    })*)
}

impl_is_minus_one! {i8 i16 i32 i64 isize}

pub fn cvt<T: IsMinusOne>(t: T) -> io::Result<T> {
    if t.is_minus_one() {
        Err(io::Error::last_os_error())
    } else {
        Ok(t)
    }
}

#[cfg(target_os = "linux")]
const TUN_PATH: &str = "/dev/net/tun";

bitflags! {
    struct TunFlags: c_short {
        const IFF_TUN = 0x0001;
        const IFF_NO_PI = 0x1000;
    }
}

bitflags! {
    struct IoctlFlags: c_ulong {
        const TUNSETIFF = 0x400454ca;
        const SIOCGIFMTU = 0x8921;
        const SIOCSIFMTU = 0x8922;
    }
}

#[repr(C)]
/* TODO
 * #[derive(Debug)]
 */
union IfrIfru {
    ifru_flags: c_short,
    ifru_mtu: c_int,
}

#[repr(C)]
/* TODO
 * #[derive(Debug)]
 */
struct Ifreq {
    ifr_name: [c_char; libc::IF_NAMESIZE],
    ifr_ifru: IfrIfru,
}

#[derive(Debug)]
pub struct Tun {
    name: String,
    file: fs::File,
    mtu: usize,
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl Read for Tun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for Tun {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Tun {
    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_mtu(&self) -> usize {
        self.mtu
    }

    pub fn set_nonblocking(&self) -> io::Result<()> {
        unsafe {
            let mut flags: c_int = 0;
            cvt(libc::fcntl(self.file.as_raw_fd(), libc::F_GETFL, 0))?;

            flags |= libc::O_NONBLOCK;
            cvt(libc::fcntl(self.file.as_raw_fd(), libc::F_SETFL, flags))?;
            Ok(())
        }
    }
}

#[derive(Debug)]
pub struct TunBuilder<'a, T>
        where T: AsRef<str> + AsRef<[u8]>, T: 'a {
    name: &'a T,
    // TODO
    ipv4_address: &'a str,
    ipv4_netmask: &'a str,
    mtu: Option<usize>,
    nonblock: bool,
}

impl<'a, T> TunBuilder<'a, T>
        where T: AsRef<str> + AsRef<[u8]> {
        // https://users.rust-lang.org/t/when-to-use-asref-t-vs-t/9312/3
    pub fn new(name: &'a T, ipv4_address: &'a str, ipv4_netmask: &'a str) -> Self {
        TunBuilder {
            name: name,
            ipv4_address: ipv4_address,
            ipv4_netmask: ipv4_netmask,
            mtu: None,
            nonblock: false,
        }
    }

    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu = Some(mtu);
    }

    pub fn set_nonblock(&mut self, nonblock: bool) {
        self.nonblock = nonblock;
    }

    pub fn up_tun(&mut self) -> io::Result<Tun> {
        let file = try!(fs::OpenOptions::new()
                                        .read(true)
                                        .write(true)
                                        .open(TUN_PATH));

        let mut ifreq = Ifreq {
            ifr_name: {
                let mut buffer = [0u8; libc::IF_NAMESIZE];
                let bytes: &[u8] = self.name.as_ref();
                let len = cmp::min(bytes.len(), libc::IF_NAMESIZE-1);
                buffer[..len].clone_from_slice(&bytes[..len]);
                unsafe {
                    mem::transmute::<[u8; libc::IF_NAMESIZE], [c_char; libc::IF_NAMESIZE]>(buffer)
                }
            },
            ifr_ifru: IfrIfru {
                ifru_flags: {
                    TunFlags::IFF_TUN.bits | TunFlags::IFF_NO_PI.bits
                },
            }
        };

        let rv = unsafe {
                libc::ioctl(file.as_raw_fd(),
                            IoctlFlags::TUNSETIFF.bits,
                            &mut ifreq)
        };
        if rv < 0 {
            return Err(io::Error::last_os_error());
        }

        let name = unsafe {
                    ffi::CStr::from_ptr(ifreq.ifr_name.as_ptr() as *const i8)
        };

        let name = name.to_owned().into_string().unwrap();
        let mtu = match self.mtu {
            Some(mtu) => {
                ifreq.ifr_ifru.ifru_mtu = mtu as i32;
                let rv = unsafe {
                        libc::ioctl(file.as_raw_fd(),
                                    IoctlFlags::SIOCSIFMTU.bits,
                                    &mut ifreq)
                };
                if rv < 0 {
                    return Err(io::Error::last_os_error());
                }
                mtu
            },
            None => {
                let rv = unsafe {
                    let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
                    libc::ioctl(sock, IoctlFlags::SIOCGIFMTU.bits, &mut ifreq)
                };
                if rv < 0 {
                    return Err(io::Error::last_os_error());
                }
                unsafe { ifreq.ifr_ifru.ifru_mtu as usize }
            }
        };

        // TODO
		self.up(&name);

        Ok(Tun {
            name: name,
            file: file,
            mtu: mtu,
        })
    }

    fn execute_command(&self, commands: &[String]) {
        for ref command in commands {
            let command: Vec<&str> = command.split_whitespace().collect();

            let status = process::Command::new(command[0])
                                .args(&command[1..])
                                .status()
                                .unwrap();

            assert!(status.success());
        }
    }

	// TODO: use netlink
    #[cfg(target_os = "linux")]
    fn up(&self, name: &str) {
        let commands = [
            format!("sysctl -w net.ipv4.conf.{}.accept_local=1", name),
            format!("ip link set {} up", name),
            format!("ip addr add {}/{} dev {}",
                        self.ipv4_address, self.ipv4_netmask, name),
            format!("ip route add default via 172.32.0.1 dev {} table 100", name),
            format!("ip rule add from all iif {} pref 10 lookup main", name),
            format!("ip rule add from all pref 100 lookup 100"),
        ];
        self.execute_command(&commands);
    }

}
