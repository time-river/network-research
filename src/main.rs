#[macro_use]
extern crate bitflags;
extern crate libc;
extern crate mio;

use std::io::{Read, Write};

use mio::{Events, Poll, Token, Ready, PollOpt};
mod driver;

use driver::{Iface, MioWrapper};

fn main() {
    let iface = Iface::new("tun0").unwrap();
    iface.up();
    let mut stream = MioWrapper::new(iface).unwrap();

    let poll = mio::Poll::new().unwrap();
    poll.register(&stream, Token(0), Ready::readable()|Ready::writable(), PollOpt::edge()).unwrap();

    let mut events = Events::with_capacity(1024);

    let mut i = 0;
    loop {
        poll.poll(&mut events, None).unwrap();

            for event in &events {
                i += 1;
                if event.token() == Token(0) && event.readiness().is_writable() {
                    println!("receive, {}, events_len={}, event={:?}", i, events.len(), event);
                    let mut buf = vec![0u8; stream.get_buffer_size()];
                    stream.read(&mut buf);
                }
            }
    }

    println!("Hello, world!");
}
