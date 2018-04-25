#[macro_use]
extern crate bitflags;
extern crate libc;
extern crate mio;
extern crate mio_extras;
extern crate ipc_channel;

mod driver;

use std::thread;
use std::io::{Read, Write};
//use std::sync::mpsc;
use ipc_channel::ipc::channel;

use mio::{Events, Poll, Token, Ready, PollOpt};

use driver::{Iface, MioWrapper};

fn main() {
// epoll
    let iface = Iface::new("tun0").unwrap();
    iface.up();

    let mut stream = MioWrapper::new(iface).unwrap();

    let poll = mio::Poll::new().unwrap();
    poll.register(&stream, Token(0), Ready::readable()|Ready::writable(), PollOpt::edge()).unwrap();

    let mut events = Events::with_capacity(1024);

    let mut i = 0;
    loop {
        let size = poll.poll(&mut events, None).unwrap();

        println!("poll return size {}", size);
        for event in &events {
            i += 1;
            if event.token() == Token(0) && event.readiness().is_readable() && event.readiness().is_writable() {
				let mut buf = vec![0u8; stream.get_buffer_size()];
                let len = stream.read(&mut buf).unwrap();
				buf.resize(len, 0);
                println!("receive, {}, events_len={}, event={:?}", i, events.len(), event);
				stream.write(&buf).unwrap();
            }
            if event.token() == Token(0) && event.readiness().is_writable() {
                println!("writable");
				let mut buf = vec![0u8; stream.get_buffer_size()];
                let len = stream.read(&mut buf);
                println!("read {:?}\n", len);
            }
        }
    }
}

/*
fn main() {
    let mut iface = Iface::new("tun0").unwrap();
    iface.up();

    let (tx_1, rx_1) = channel().unwrap();
    let (tx_2, rx_2) = channel().unwrap();

    let mut i = 0;
    thread::spawn(move || {
        let tx = tx_2;
        let rx = rx_1;

        loop {
            let buf: Vec<u8> = rx.recv().unwrap();
            i += 1;
            println!("receive from main, size={}, i={}", buf.len(), i);
            tx.send(buf).unwrap();
        }
    });

    let tx = tx_1;
    let rx = rx_2;

    loop {
        let mut buf = vec![0u8; iface.get_mtu().unwrap()];
        let len = iface.read(&mut buf).unwrap();
        buf.resize(len, 0);
        println!("send, size={}, i={}", buf.len(), i);
        tx.send(buf).unwrap();
        let buffer: Vec<u8> = rx.recv().unwrap();
        iface.write(&buffer).unwrap();
        drop(buffer);
    }

}
*/
