use std::net::Ipv4Addr;
use crate::builders::packets::Checksum;



pub(crate) struct UdpPkt {
    buffer: [u8; 347],
}


impl UdpPkt {

    pub fn new() -> Self {
        let buffer = Self::build_fixed();
        Self{ buffer }
    }



    fn build_fixed() -> [u8; 347] {
        let mut buffer = [0u8; 347];

        // IP header (0 - 20)
        buffer[0] = (4 << 4) | 5;
        buffer[1] = 0;
        buffer[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        buffer[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        buffer[8] = 64;
        buffer[9] = 17;
        buffer[10..12].copy_from_slice(&0u16.to_be_bytes());

        // UDP header (20 - 28)
        buffer[26..28].copy_from_slice(&0u16.to_be_bytes());

        buffer
    }



    #[inline]
    fn ip_header(
        &mut self,
        len      : u16,
        src_ip   : Ipv4Addr,
        dst_ip   : Ipv4Addr
    ) {
        // 0..1 pre built
        self.buffer[2..4].copy_from_slice(&len.to_be_bytes());
        // 4..12 prebuilt
        self.buffer[12..16].copy_from_slice(&src_ip.octets());
        self.buffer[16..20].copy_from_slice(&dst_ip.octets());

        let cksum = Checksum::ipv4_checksum(&self.buffer[..20]);
        self.buffer[10..12].copy_from_slice(&cksum.to_be_bytes());
    }



    #[inline]
    fn udp_header(
        &mut self,
        src_ip      : Ipv4Addr,
        src_port    : u16,
        dst_ip      : Ipv4Addr,
        dst_port    : u16,
        len_payload : u16
    ) {
        let len = 8 + len_payload;

        self.buffer[20..22].copy_from_slice(&src_port.to_be_bytes());
        self.buffer[22..24].copy_from_slice(&dst_port.to_be_bytes());
        self.buffer[24..26].copy_from_slice(&len.to_be_bytes());
        // 26..28 pre built
        
        let cksum = Checksum::tcp_udp_checksum(&self.buffer[..len as usize], src_ip, dst_ip, 17);
        self.buffer[26..28].copy_from_slice(&cksum.to_be_bytes());
    }



    #[inline]
    pub fn l3_pkt(
        &mut self,
        src_ip   : Ipv4Addr,
        src_port : u16,
        dst_ip   : Ipv4Addr,
        dst_port : u16,
        payload  : &[u8]
    ) 
      -> &[u8]
    {
        let len_payload : usize = payload.len().try_into().unwrap();
        let len_pkt     : usize = 28 + len_payload;
        
        self.buffer[28..len_pkt].copy_from_slice(&payload);

        self.udp_header(src_ip, src_port, dst_ip, dst_port, len_payload as u16);
        self.ip_header(len_pkt as u16, src_ip, dst_ip);

        &self.buffer[..len_pkt]
    }

}