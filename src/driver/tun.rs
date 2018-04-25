use std::{cmp, ffi, fs, io, mem, process};
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};

use libc;
use libc::{c_char, c_short, c_int};

use driver::{cvt};
use driver::{IoctlFlags, TunFlags, TUN_PATH};

#[repr(C)]
union IfrIfru {
    ifru_flags: c_short,
    ifru_mtu: c_int,
}

#[repr(C)]
struct Ifreq {
    ifr_name: [c_char; libc::IF_NAMESIZE],
    ifr_ifru: IfrIfru,
}

#[derive(Debug)]
pub struct Tun {
	name: String,
    file: fs::File,
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

    pub fn new(name: &str) -> io::Result<Self> {
        let file = try!(fs::OpenOptions::new()
                                        .read(true)
                                        .write(true)
                                        .open(TUN_PATH));
    
        let mut ifreq = Ifreq {
            ifr_name: {
                let mut buffer = [0u8; libc::IF_NAMESIZE];
                let bytes: &[u8] = name.as_ref();
                let len = cmp::min(bytes.len(), libc::IF_NAMESIZE-1);
                buffer[..len].clone_from_slice(&bytes[..len]);
                unsafe {
                    mem::transmute::
                        <[u8; libc::IF_NAMESIZE], [c_char; libc::IF_NAMESIZE]>
                        (buffer)
                }
            },
            ifr_ifru: IfrIfru {
                ifru_flags: {
                    TunFlags::IFF_TUN.bits | TunFlags::IFF_NO_PI.bits
                },
            },
        };
    
        cvt(unsafe {
            libc::ioctl(file.as_raw_fd(),
                        IoctlFlags::TUNSETIFF.bits,
                        &mut ifreq)
        })?;

        let name = unsafe {
                    ffi::CStr::from_ptr(ifreq.ifr_name.as_ptr() as *const i8)
        };
        let name = name.to_owned().into_string().unwrap();

        Ok(Tun {
            name: name,
            file: file,
        })        
    }

	pub fn get_name(&self) -> &str {
		&self.name
	}

	pub fn get_mtu(&self) -> io::Result<usize> {
        let mut ifreq = Ifreq {
            ifr_name: {
                let mut buffer = [0u8; libc::IF_NAMESIZE];
                let bytes: &[u8] = self.name.as_ref();
                let len = cmp::min(bytes.len(), libc::IF_NAMESIZE-1);
                buffer[..len].clone_from_slice(&bytes[..len]);
                unsafe {
                    mem::transmute::
                        <[u8; libc::IF_NAMESIZE], [c_char; libc::IF_NAMESIZE]>
                        (buffer)
                }
		    },
            ifr_ifru: IfrIfru { ifru_mtu: 0 },
        };

		unsafe {
			let sock = cvt(libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0))?;
            cvt(libc::ioctl(sock, IoctlFlags::SIOCGIFMTU.bits, &mut ifreq))?;
            Ok(ifreq.ifr_ifru.ifru_mtu as usize)
		}
	}

    pub fn set_nonblocking(&self) -> io::Result<()> {
        unsafe {
            let mut flags: c_int = 0;
            cvt(libc::fcntl(self.as_raw_fd(), libc::F_GETFL, 0))?;

            flags |= libc::O_NONBLOCK;
            cvt(libc::fcntl(self.as_raw_fd(), libc::F_SETFL, flags))?;
            Ok(())
        }
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
    pub fn up(&self) {
        let commands = [
            format!("sysctl -w net.ipv4.conf.{}.accept_local=1", self.name),
            format!("ip link set {} up", self.name),
            format!("ip addr add 172.32.0.1/24 dev {}", self.name),
            format!("ip route add default via 172.32.0.1 dev {} table 100", self.name),
            format!("ip rule add from all iif {} pref 10 lookup main", self.name),
            format!("ip rule add from all pref 100 lookup 100"),
        ];
        self.execute_command(&commands);
    }

}
