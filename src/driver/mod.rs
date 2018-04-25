use std::io;

use libc::{c_short, c_ulong};

mod tun;
mod wrapper;

pub use driver::tun::Tun as Iface;
pub use driver::wrapper::MioWrapper;

trait IsMinusOne {
    fn is_minus_one(&self) -> bool;
}

macro_rules! impl_is_minus_one {
    ($($t:ident)*) => ($(impl IsMinusOne for $t {
        fn is_minus_one(&self) -> bool {
            *self == -1
        }
    })*)
}

impl_is_minus_one!{ i32 }

fn cvt<T: IsMinusOne>(t: T) -> io::Result<T> {
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
