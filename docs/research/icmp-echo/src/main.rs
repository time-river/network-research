
extern crate libc;

//use std::os::unix::io::RawFd;
use std::ffi::CString;
//use std::ffi::CStr;
use std::io;
use std::fs;
use std::path;
use std::slice;
use std::mem;
use std::string;
use std::os::unix::io::AsRawFd;
use std::io::{Read, Write};

use std::process;

use libc::c_char;
use libc::c_short;
use libc::c_int;
use libc::c_ulong;
use libc::ioctl;
use libc::socket;
use libc::AF_INET;
use libc::SOCK_DGRAM;

const TUN_PATH: &str = "/dev/net/tun";
const TUN_NAME: &str= "tun0";
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

struct Tun {
    name: String,
    handle: fs::File,
    mtu: i32,
}

impl Tun {
    pub fn create(name: &str) -> Result<Tun, io::Error> {
        let path = path::Path::new(TUN_PATH);
        let file = try!(fs::OpenOptions::new().read(true).write(true).open(&path));

        let mut req = Ifreq {
            ifr_name: {
                let mut buffer = [0i8; IFNAMSIZ];
                let tun_name: Vec<i8> = String::from(name).as_bytes().into_iter().map(|w| *w as i8).collect();
                buffer[..tun_name.len()].clone_from_slice(&tun_name);
                buffer
            },
            ifr_ifru: Ifrifru { ifru_flags: IFF_TUN | IFF_NO_PI },
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
            name: String::from(TUN_NAME),
            handle: file,
            mtu: unsafe { req.ifr_ifru.ifru_mtu },
        };

        Ok(tun)
    }

    pub fn up(&self) {
        let status = process::Command::new("ip")
                            .args(&["link", "set", &format!("{}", self.name), "up"])
                            .status()
                            .expect("...");
        assert!(status.success());

        let status = process::Command::new("ip")
                            .args(&["addr", "add", "10.0.0.2/24", "dev", &format!("{}", self.name)])
                            .status()
                            .expect("...");
        assert!(status.success());

        let status = process::Command::new("ip")
                            .args(&["route", "add", "default", "via", "10.0.0.2", "dev", &format!("{}", self.name), "table", "100"])
                            .status()
                            .expect("...");
        assert!(status.success());

        let status = process::Command::new("ip")
                            .args(&["rule", "add", "from", "all", "iif", &format!("{}", self.name), "pref", "10", "lookup", "main"])
                            .status()
                            .expect("...");
        assert!(status.success());

        let status = process::Command::new("sysctl")
                            .args(&["-w", &format!("net.ipv4.conf.{}.accept_local=1", self.name)])
                            .status()
                            .expect("...");
        assert!(status.success());

        let status = process::Command::new("ip")
                            .args(&["rule", "add", "from", "all", "pref", "100", "lookup", "100"])
                            .status()
                            .expect("...");
        assert!(status.success());

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

#[repr(packed)]
pub struct IPv4Header {
    pub version_ihl: u8, // IP version (= 4) + Internet header length
    pub type_of_service: u8, // Type of service
    pub total_length: u16, // Total length in octets
    pub identification: u16, // Identification
    pub flags_fragment_offset: u16, // 3-bits Flags + Fragment Offset
    pub time_to_live: u8, // Time To Live
    pub protocol: u8, // Protocol
    pub header_checksum: u16, // Checksum
    pub source_address: u32, // Source Address
	pub destination_address: u32, // Destination Address
}

#[repr(packed)]
pub struct ICMPHeader {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub icmp_checksum: u16,
    pub icmp_ident: u16,
    pub icmp_seq_num: u16,
}

fn icmp_cksum(data: &[u8]) -> u16 {
    raw_cksum(data.as_ptr() as *const u16, data.len())
}

fn raw_cksum<T>(buf: *const T, len: usize) -> u16 {
	let mut sum = 0u32;
    let mut remaining_len = len;
    let mut ptr = buf as *const u16;
    while remaining_len > 1 {
        unsafe {
            sum += *ptr as u32;
            ptr = ptr.offset(1);
        }
        remaining_len -= 2;
    }

    if remaining_len == 1 {
        unsafe {
            sum += *(ptr as *const u8) as u32;
        }
    }

    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    !sum as u16
}

fn ipv4_cksum(data: &[u8]) -> u16 {
    raw_cksum(data.as_ptr() as *const IPv4Header, mem::size_of::<IPv4Header>())
}

fn ipv4_header_parse(data: &[u8]) {
    let header = unsafe { &*(data.as_ptr() as *const IPv4Header) };
    println!("version_ihl=0x{:x}, type_of_service=0x{:x}, total_length={}, identification={}, time_to_live=0x{:x}, header_checksum=0x{:x}, src={}, dst={}, protocol=0x{:x}",
             header.version_ihl, header.type_of_service, u16::from_be(header.total_length), u16::from_be(header.identification), header.time_to_live,
             header.header_checksum, pretty_print_ipv4(header.source_address), pretty_print_ipv4(header.destination_address), header.protocol);
    if header.protocol == 0x01 {
        icmp_header_parse(&data[20..]);
    }
}

fn pretty_print_ipv4(address: u32) -> String {
    let address = u32::from_be(address);
    format!("{}.{}.{}.{}", address >> 24 & 0xFF, address >> 16 & 0x00FF, address >> 8 & 0x0000FF, address & 0x000000FF)
}

fn icmp_header_parse(data: &[u8]) {
    let header = unsafe { &*(data.as_ptr() as *const ICMPHeader) };
    println!("  icmp_type=0x{:x}, icmp_code=0x{:x}, icmp_checksum={:x}, icmp_ident={}, icmp_seq_num={}",
             header.icmp_type, header.icmp_code, header.icmp_checksum, u16::from_be(header.icmp_ident), u16::from_be(header.icmp_seq_num));
}

fn main() {
            /*
            let mut buffer = [0i8; IFNAMSIZ];
            let tun_name = String::from(TUN_NAME);
            let tun_name_array_i8 = unsafe { mem::transmute::<&[u8], &[i8]>(tun_name.as_bytes()) };
            buffer[..tun_name.len()].clone_from_slice(tun_name_array_i8);
            buffer
            */
    let mut tun = Tun::create(TUN_NAME).unwrap();
    tun.up();

    println!("file={:?}, mtu={}", tun.handle, tun.mtu);
    let mut data = vec![0u8; tun.mtu as usize];
    let mut len: usize = 0;

    loop {
        match tun.read(&mut data) {
            Ok(l) => {
                println!("length={}", l);
                len = l;
            },
            Err(e) => {} ,
        }

        ipv4_header_parse(&data);
        tun.write(&data);
    }
}
