/*
 * Reference:
 *  https://github.com/faern/rips/blob/master/packets/src/ipv4.rs
 *
 * Date: Apr 19 CST 2018
 */

/*
    ICMP Request format:
         0         7 8        15 16                  31 
        +-----------+-----------+----------------------+
        |    Type   |    Code   | ICMP_Header_Checksum |
        +-----------+-----------+----------------------+
        |       Identifier      |   Sequence_number    |
        +-----------------------+----------------------+
        |                     Data                     |
        +----------------------------------------------+

    reference:
        http://www.networksorcery.com/enp/protocol/icmp/msg8.htm


    ICMP Echo format:
         0         7 8        15 16                  31 
        +-----------+-----------+----------------------+
        |    Type   |    Code   | ICMP_Header_Checksum |
        +-----------+-----------+----------------------+
        |       Identifier      |   Sequence_number    |
        +-----------------------+----------------------+
        |                     Data                     |
        +----------------------------------------------+

     RFC 792, page 15:

         The data received in the echo request message must be returned in the echo reply message.

     calculate checksum

    reference:
        http://www.networksorcery.com/enp/protocol/icmp/msg0.htm
        http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
        http://arondight.me/2016/03/22/%E8%AE%A1%E7%AE%97IP%E3%80%81ICMP%E3%80%81TCP%E5%92%8CUDP%E5%8C%85%E7%9A%84%E6%A0%A1%E9%AA%8C%E5%92%8C/
*/

packet!(ICMPPacket, MutICMPPacket, 8);

getters!(ICMPPacket
    pub fn icmp_type(&self) -> u8 {
        read_offset!(self.0, 0, u8)
    }

    pub fn icmp_code(&self) -> u8 {
        read_offset!(self.0, 1, u8)
    }

    pub fn header_checksum(&self) -> u16 {
        read_offset!(self.0, 2, u16, from_be)
    }

    pub fn identifier(&self) -> u16 {
        read_offset!(self.0, 4, u16, from_be)
    }

    pub fn sequence_number(&self) -> u16 {
        read_offset!(self.0, 6, u16, from_be)
    }
);

setters!(MutICMPPacket
    pub fn set_icmp_type(&mut self, icmp_type: u8) {
        write_offset!(self.0, 0, icmp_type, u8);
    }

    pub fn set_icmp_code(&mut self,icmp_code: u8) {
        write_offset!(self.0, 1, icmp_code, u8);
    }

    pub fn set_header_checksum(&mut self, checksum: u16) {
        write_offset!(self.0, 2, checksum, u16);
    }
);
