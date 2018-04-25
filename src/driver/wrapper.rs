use std::io;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;

use mio::{Evented, Ready, Poll, PollOpt, Token};
use mio::unix::EventedFd;

use driver::Iface;

pub struct MioWrapper {
    iface: Iface,
    buffer_size: usize,
}

impl Evented for MioWrapper {

    fn register(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt)
        -> io::Result<()> {
        EventedFd(&self.iface.as_raw_fd()).register(poll, token, interest, opts)
    }

    fn reregister(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt)
        -> io::Result<()> {
        EventedFd(&self.iface.as_raw_fd()).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        EventedFd(&self.iface.as_raw_fd()).deregister(poll)
    }
}

impl Read for MioWrapper {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.iface.read(buf)
    }
}

impl Write for MioWrapper {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.iface.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.iface.flush()
    }
}

impl MioWrapper {

    pub fn new(iface: Iface) -> io::Result<Self> {
        let size = iface.get_mtu()?;

        iface.set_nonblocking()?;
        Ok(MioWrapper {
            iface: iface,
            buffer_size: size,
        })
    }

    pub fn get_buffer_size(&self) -> usize {
        self.buffer_size
    }
}
