/*
 * Reference:
 *  https://github.com/changlan/kytan/blob/master/src/device.rs
 *
 * Date: Apr 17 CST 2018
 */

use std::{fs, io, path, process};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;

use libc::{
    c_char, c_short, c_int, c_ulong,
    ioctl, socket, AF_INET, SOCK_DGRAM
};

const TUN_PATH: &str = "/dev/net/tun";
const IFNAMSIZ: usize = 16;
const TUNSETIFF: c_ulong = 0x400454ca; // https://stackoverflow.com/questions/22496123/what-is-the-meaning-of-this-macro-iormy-macig-0-int
const SIOCGIFMTU: c_ulong = 0x8921;
const IFF_TUN: c_short = 0x0001;
const IFF_NO_PI: c_short = 0x1000;

#[repr(C)]
union Ifrifru {
    ifru_flags: c_short,
    ifru_mtu: c_int,
}

#[repr(C)]
struct Ifreq {
    ifr_name: [c_char; IFNAMSIZ],
    ifr_ifru: Ifrifru,
}

pub struct Tun {
    pub ifr_name: String,
    pub handle: fs::File,
    pub mtu: usize,
}

impl Tun {
    #[cfg(target_os = "linux")]
    pub fn create(name: &str) -> Result<Tun, io::Error> {
        if name.len() >= IFNAMSIZ {
            return Err(io::Error::new(io::ErrorKind::Other, format!("name length is large than {}", IFNAMSIZ)));
        }

        let path = path::Path::new(TUN_PATH);
        let file = try!(fs::OpenOptions::new().read(true).write(true).open(path));

        let mut req = Ifreq {
            ifr_name: {
                let mut buffer = [0i8; IFNAMSIZ];
                let name: Vec<i8> = name.as_bytes().into_iter().map(|w| *w as i8).collect();
                buffer[..name.len()].clone_from_slice(&name);
                buffer
        },
            ifr_ifru: Ifrifru { 
                ifru_flags: IFF_TUN | IFF_NO_PI },
        };

        let rv = unsafe { ioctl(file.as_raw_fd(), TUNSETIFF, &mut req) };
        if rv < 0 {
            return Err(io::Error::last_os_error());
        }

        let sock = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
        let rv = unsafe { ioctl(sock, SIOCGIFMTU, &mut req) };
        if rv < 0 {
            return Err(io::Error::last_os_error());
        }

        let tun = Tun {
            ifr_name: String::from(name),
            handle: file,
            mtu: unsafe { req.ifr_ifru.ifru_mtu } as usize,
        };

        Ok(tun)
    }

    fn execute_command(commands: &[String]) {
        for ref command in commands {
            let command: Vec<&str> = command.split_whitespace().collect();

            let status = process::Command::new(command[0])
                                .args(&command[1..])
                                .status()
                                .unwrap();

            assert!(status.success());
        }
    }

    #[cfg(target_os = "linux")]
    pub fn up(&self) {
        let commands = [
            format!("sysctl -w net.ipv4.conf.{}.accept_local=1", self.ifr_name),
            format!("ip link set {} up", self.ifr_name),
            format!("ip addr add 172.32.0.1/24 dev {}", self.ifr_name),
            format!("ip route add default via 172.32.0.1 dev {} table 100", self.ifr_name),
            format!("ip rule add from all iif {} pref 10 lookup main", self.ifr_name),
            format!("ip rule add from all pref 100 lookup 100"),
        ];
        Tun::execute_command(&commands);
    }

    #[cfg(target_os = "linux")]
    pub fn down(&self) {
        let commands = [
            format!("ip rule del from all pref 100 lookup 100"),
            format!("ip rule del from all iif {} pref 10 lookup main", self.ifr_name),
            format!("ip route del default via 172.32.0.1 dev {} table 100", self.ifr_name),
            format!("ip addr del 172.32.0.1/24 dev {}", self.ifr_name),
            format!("ip link set {} down", self.ifr_name),
        ];
        Tun::execute_command(&commands);
    }

}

impl Read for Tun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.handle.read(buf)
    }
}

impl Write for Tun {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.handle.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.handle.flush()
    }
}
