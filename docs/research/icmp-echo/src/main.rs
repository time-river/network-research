/*
 * This's a program that:
 *  catch all IPv4 packet, then fake icmp echo if the catched IPv4 packet is icmp request, or
 *  directly out of local.
 */

extern crate libc;

mod types;
#[macro_use]
mod macros;
mod checksum;
mod device;
mod ipv4;
mod icmp;

use std::process;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use device::Tun;
use ipv4::{IPv4Packet, MutIPv4Packet};
use icmp::{ICMPPacket, MutICMPPacket};
use checksum::raw_checksum;

const TUN_NAME: &str = "tun0";
static mut TUN: Option<Tun> = None;

fn cleanup(signum: i32) {
    if signum == libc::SIGINT {
        unsafe {
            match TUN {
                Some(ref tun) =>
                    tun.down(),
                None => {},
            }
        }
        process::exit(0);
    }
}

fn unwrap_tun() -> &'static mut Tun {
    unsafe {
        match TUN {
            Some(ref mut x) => x,
            None => panic!(),
        }
    }
}

fn icmp_echo(ori_ipv4_packet: IPv4Packet, total_len: usize) -> Option<Vec<u8>> {
    let payload_len =
        (ori_ipv4_packet.total_length() - ori_ipv4_packet.header_length() as u16 * 4) as usize;
    let ori_icmp = ICMPPacket::new(ori_ipv4_packet.payload())
                                .expect("ICMPHeader new failed");

    if ori_icmp.icmp_type() != 0x08 {
        return None;
    }

    let icmp_request = ori_icmp;

    println!("  icmp_request:\n    type=0x{:02x} code=0x{:02x} header_checksum=0x{:04x} identifier=0x{:04x} sequence_number={}\n",
             icmp_request.icmp_type(),
             icmp_request.icmp_code(),
             icmp_request.header_checksum(),
             icmp_request.identifier(),
             icmp_request.sequence_number());

    let mut data: Vec<u8> = vec![0u8; total_len];
    {
        let mut payload: Vec<u8> = vec![0u8; payload_len];
        let mut icmp_echo = MutICMPPacket::new(&mut payload)
                                        .expect("ICMPPacket new failed");
        icmp_echo.set_icmp_type(0u8);
        icmp_echo.set_icmp_code(0u8);
        icmp_echo.set_header_checksum(0u16);
        icmp_echo.data()[4..].clone_from_slice(&(icmp_request.data()[4..payload_len]));
        
        let checksum = raw_checksum(icmp_echo.data().as_ptr(), icmp_echo.data().len());
        icmp_echo.set_header_checksum(checksum);

        let mut ipv4_packet = MutIPv4Packet::new(&mut data).expect("IPv4Packet new failed");
        ipv4_packet.data()
                    [..IPv4Packet::MIN_LEN]
                    .clone_from_slice(&ori_ipv4_packet.data()[..IPv4Packet::MIN_LEN]);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_payload(&icmp_echo.data());
        ipv4_packet.set_header_checksum(0);
        ipv4_packet.set_source_address(ori_ipv4_packet.destination_address());
        ipv4_packet.set_destination_address(ori_ipv4_packet.source_address());
        ipv4_packet.set_identification(ori_ipv4_packet.identification() & 0xf8ff); // random identification
        let checksum = raw_checksum(ipv4_packet.data().as_ptr(), ipv4_packet.data().len());
        ipv4_packet.set_header_checksum(checksum);

        let ipv4_packet = ipv4_packet.as_immutable();
        println!("ipv4_packet:\n    version={} header_length={} total_length=0x{:04x} identification=0x{:04x} ttl={} protocol=0x{:02x} header_checksum=0x{:04x} source_address={} destination_address={}",
                 ipv4_packet.version(),
                 ipv4_packet.header_length(),
                 ipv4_packet.total_length(),
                 ipv4_packet.identification(),
                 ipv4_packet.ttl(),
                 ipv4_packet.protocol(),
                 ipv4_packet.header_checksum(),
                 Ipv4Addr::from(ipv4_packet.source_address()),
                 Ipv4Addr::from(ipv4_packet.destination_address()));

        let icmp_echo = icmp_echo.as_immutable();
        println!("  icmp_echo:\n    type=0x{:02x} code=0x{:02x} header_checksum=0x{:04x} identifier=0x{:04x} sequence_number={}\n",
                 icmp_echo.icmp_type(),
                 icmp_echo.icmp_code(),
                 icmp_echo.header_checksum(),
                 icmp_echo.identifier(),
                 icmp_echo.sequence_number());
    }
    Some(data)
}

fn main() {

    match Tun::create(TUN_NAME) {
        Ok(result) => unsafe {
            result.up();
            TUN = Some(result);
        },
        Err(e) => panic!(e),
    };

    unsafe {
        libc::signal(libc::SIGINT, cleanup as usize);
    }

    let tun = unwrap_tun();

    loop {
        let mut buffer = vec![0u8; tun.mtu];
        let total_len = tun.read(buffer.as_mut_slice()).unwrap();
        let ipv4_packet = IPv4Packet::new(buffer.as_slice())
                                    .expect("IPv4Packet new failed.");
        println!("ori_ipv4_packet:\n    version={} header_length={} total_length=0x{:04x} identification=0x{:04x} ttl={} protocol=0x{:02x} header_checksum=0x{:04x} source_address={} destination_address={}",
                 ipv4_packet.version(),
                 ipv4_packet.header_length(),
                 ipv4_packet.total_length(),
                 ipv4_packet.identification(),
                 ipv4_packet.ttl(),
                 ipv4_packet.protocol(),
                 ipv4_packet.header_checksum(),
                 Ipv4Addr::from(ipv4_packet.source_address()),
                 Ipv4Addr::from(ipv4_packet.destination_address()));
        if ipv4_packet.protocol() == 0x01 {
            match icmp_echo(ipv4_packet, total_len) {
                Some(data) => {
                    let _ = tun.write(data.as_slice());
                },
                None => {
                    let _ = tun.write(buffer.as_slice());
                },
            };
            continue;
        }
        let _ = tun.write(buffer.as_slice());
    }
}
