use std::net::Ipv4Addr;
use crate::builders::packets::Checksum;
use crate::utils::Mac;



pub(crate) struct IcmpPkt {
    buffer: [u8; 42],
}


impl IcmpPkt {

    pub fn new() -> Self {
        let buffer = Self::build_fixed();
        Self { buffer }
    }



    fn build_fixed() -> [u8; 42] {
        let mut buffer = [0u8; 42];

        // Ethernet header (0 - 14)
        buffer[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

        // IP header (14 - 34)
        buffer[14] = (4 << 4) | 5;
        buffer[15] = 0;
        buffer[16..18].copy_from_slice(&28u16.to_be_bytes());
        buffer[18..20].copy_from_slice(&0x1234u16.to_be_bytes());
        buffer[20..22].copy_from_slice(&0x4000u16.to_be_bytes());
        buffer[22] = 64;
        buffer[23] = 1;
        buffer[24..26].copy_from_slice(&0u16.to_be_bytes());

        // ICMP header (34 - 42)
        buffer[34] = 8;
        buffer[35] = 0;
        buffer[36..38].copy_from_slice(&0u16.to_be_bytes());
        buffer[38..40].copy_from_slice(&0x1234u16.to_be_bytes()); 
        buffer[40..42].copy_from_slice(&1u16.to_be_bytes());

        let cksum = Checksum::icmp_checksum(&buffer[34..42]);
        buffer[36..38].copy_from_slice(&cksum.to_be_bytes());

        buffer
    }



    #[inline]
    fn ether_header(
        &mut self,
        src_mac : Mac,
        dst_mac : Mac
    ) {
        self.buffer[..6].copy_from_slice(dst_mac.bytes());
        self.buffer[6..12].copy_from_slice(src_mac.bytes());
        // 12..14 pre built
    }



    #[inline]
    fn ip_header(
        &mut self,
        src_ip : Ipv4Addr,
        dst_ip : Ipv4Addr
    ) {
        // 14..26 pre built
        self.buffer[26..30].copy_from_slice(&src_ip.octets());
        self.buffer[30..34].copy_from_slice(&dst_ip.octets());

        let cksum = Checksum::ipv4_checksum(&self.buffer[14..34]);
        self.buffer[24..26].copy_from_slice(&cksum.to_be_bytes());
    }



    #[inline]
    pub fn l3_pkt(
        &mut self,
        src_ip : Ipv4Addr,
        dst_ip : Ipv4Addr,
    ) 
      -> &[u8]
    {
        self.ip_header(src_ip, dst_ip);
        &self.buffer[14..42]
    }




    #[inline]
    pub fn l2_pkt(
        &mut self,
        src_mac : Mac,
        src_ip  : Ipv4Addr,
        dst_mac : Mac,
        dst_ip  : Ipv4Addr,
    ) 
      -> &[u8]
    {
        self.ip_header(src_ip, dst_ip);
        self.ether_header(src_mac, dst_mac);

        &self.buffer[..42]
    }

}