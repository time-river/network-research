#[macro_use]
extern crate bitflags;
extern crate libc;
extern crate mio;
extern crate mio_extras;

mod driver;

use std::thread;
use std::vec::Vec;
use std::io::{Read, Write};

use mio::{Events, Token, Ready, PollOpt};
use mio_extras::channel::channel;

use driver::{Iface, MioWrapper};

fn main() {
    let iface = Iface::new("tun0").unwrap();
    iface.up();

    let mut stream = MioWrapper::new(iface).unwrap();

    let (tx_1, rx_1) = channel();
    let (tx_2, rx_2) = channel();

    let _ = thread::spawn(move || {
        let (tx, rx) = (tx_2, rx_1);

        let mut events = Events::with_capacity(1024);

        let poll = mio::Poll::new().unwrap();
        poll.register(&rx, Token(1), Ready::readable(), PollOpt::level()).unwrap();

        loop {

            let size = poll.poll(&mut events, None).unwrap();

            println!("subthread size={}", size);
            for event in &events {
                if event.token() == Token(1) && event.readiness().is_readable() {
                    let buf: Vec<u8> = rx.try_recv().unwrap();
                    println!("recv from main, size={}", buf.len());
                    tx.send(buf).unwrap();
                }
            }
        }
    });
    
    let (tx, rx) = (tx_1, rx_2);

    let poll = mio::Poll::new().unwrap();
    poll.register(&rx, Token(1), Ready::readable(), PollOpt::level()).unwrap();
    poll.register(&stream, Token(0), Ready::readable(), PollOpt::level()).unwrap();

    let mut events = Events::with_capacity(1024);

    let mut i = 0;
    loop {
        let size = poll.poll(&mut events, None).unwrap();

        println!("main size={}", size);
        for event in &events {
            i += 1;
            if event.token() == Token(0) && event.readiness().is_readable() {
				let mut buf = vec![0u8; stream.get_buffer_size()];
                let len = stream.read(&mut buf).unwrap();
				buf.resize(len, 0);
                println!("receive, {}, event={:?}", i, event);
                tx.send(buf).unwrap();
            } else if event.token() == Token(1) && event.readiness().is_readable() {
                let buf: Vec<u8> = rx.try_recv().unwrap();
                println!("receive from slave, size={}", buf.len());
				stream.write(&buf).unwrap();
            }
        }
    }
}
