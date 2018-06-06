/*
 * Reference:
 *  https://github.com/faern/rips/blob/master/packets/src/ipv4.rs
 *
 * Date: Apr 19 CST 2018
 */

use types::u4;

packet!(IPv4Packet, MutIPv4Packet, 20);

getters!(IPv4Packet
    pub fn version(&self) -> u4 {
        read_offset!(self.0, 0, u8) >> 4
    }

    pub fn header_length(&self) -> u4 {
        read_offset!(self.0, 0, u8) & 0x0f
    }

    pub fn total_length(&self) -> u16 {
        read_offset!(self.0, 2, u16, from_be)
    }

    pub fn identification(&self) -> u16 {
        read_offset!(self.0, 4, u16, from_be)
    }

    pub fn ttl(&self) -> u8 {
        read_offset!(self.0, 8, u8)
    }

    pub fn protocol(&self) -> u8 {
        read_offset!(self.0, 9, u8)
    }

    pub fn header_checksum(&self) -> u16 {
        read_offset!(self.0, 10, u16, from_be)
    }

    pub fn source_address(&self) -> u32 {
        read_offset!(self.0, 12, u32, from_be)
    }

    pub fn destination_address(&self) -> u32 {
        read_offset!(self.0, 16, u32, from_be)
    }

    pub fn payload(&self) -> &[u8] {
        let len = (self.header_length() * 4) as usize;
        &self.0[len..]
    }
);

setters!(MutIPv4Packet
    pub fn set_header_length(&mut self, header_length: u4) {
        let new_byte = (read_offset!(self.0, 0, u8) & 0xf0) | (header_length & 0x0f);
        write_offset!(self.0, 0, new_byte, u8);
    }

    pub fn set_identification(&mut self, identification: u16) {
        write_offset!(self.0, 4, identification, u16, to_be);
    }

    pub fn set_header_checksum(&mut self, checksum: u16) {
        write_offset!(self.0, 10, checksum, u16);
    }

    pub fn set_source_address(&mut self, source_address: u32) {
        write_offset!(self.0, 12, source_address, u32, to_be);
    }

    pub fn set_destination_address(&mut self, destination_address: u32) {
        write_offset!(self.0, 16, destination_address, u32, to_be);
    }

    pub fn set_payload(&mut self, payload: &[u8]) {
        let len = ((read_offset!(self.0, 0, u8) & 0x0f) * 4) as usize;
        self.0[len..].clone_from_slice(payload);
    }
);
