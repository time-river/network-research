/* https://github.com/polachok/tuntap/blob/master/src/lib.rs */


use std::{cmp, ffi, fs, io, mem};
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use libc;
use libc::{c_char, c_short, c_int, c_ulong};

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
    }
}

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

#[derive(Debug)]
pub struct TunBuilder<'a, T>
        where T: AsRef<str> + AsRef<[u8]>, T: 'a {
    name: Option<&'a T>,
}

impl<'a, T> TunBuilder<'a, T>
        where T: AsRef<str> + AsRef<[u8]> {
        // https://users.rust-lang.org/t/when-to-use-asref-t-vs-t/9312/3
    pub fn new(name: &'a T) -> Self {
        TunBuilder {
            name: Some(name),
        }
    }

    pub fn open_tun(&mut self) -> io::Result<Tun> {
        let file = try!(fs::OpenOptions::new()
                                        .read(true)
                                        .write(true)
                                        .open(TUN_PATH));

        let name = self.name.unwrap();

        let mut ifreq = Ifreq {
            ifr_name: {
                let mut buffer = [0u8; libc::IF_NAMESIZE];
                let bytes: &[u8] = name.as_ref();
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

        let rv = unsafe {
                let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
                libc::ioctl(sock, IoctlFlags::SIOCGIFMTU.bits, &mut ifreq)
        };
        if rv < 0 {
            return Err(io::Error::last_os_error());
        }

        let name = unsafe {
                    ffi::CStr::from_ptr(ifreq.ifr_name.as_ptr() as *const i8)
        };
        let name = name.to_owned().into_string().unwrap();

        Ok(Tun {
            name: name,
            file: file,
            mtu: unsafe { ifreq.ifr_ifru.ifru_mtu } as usize,
        })
    }
}
