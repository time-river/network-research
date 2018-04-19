/*
 * Reference:
 *  https://github.com/changlan/kytan/blob/master/src/packet.rs
 *  https://github.com/libpnet/libpnet/blob/master/pnet_packet/src/util.rs
 *
 * Date: Apr 19 CST 2018
 */

pub fn raw_checksum<T>(buf: *const T, len: usize) -> u16 {
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
        sum = (sum >> 16) + (sum & 0xffff);
    }

    !sum as u16
}
