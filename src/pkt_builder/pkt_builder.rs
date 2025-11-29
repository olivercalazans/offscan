use std::net::Ipv4Addr;
use crate::pkt_builder::HeaderBuilder;



pub struct PacketBuilder {
    buffer: [u8; 347],
}



impl PacketBuilder {

    pub fn new() -> Self {
        Self { buffer: [0; 347] }
    }



    #[inline]
    pub fn tcp_ip(
        &mut self,
        src_ip:   Ipv4Addr,
        src_port: u16,
        dst_ip:   Ipv4Addr,
        dst_port: u16,
        ) -> &[u8]
    {
        HeaderBuilder::tcp(&mut self.buffer[20..40], src_ip, src_port, dst_ip, dst_port);
        HeaderBuilder::ip(&mut self.buffer[..20], 40, 6, src_ip, dst_ip);
        
        &self.buffer[..40]
    }



    #[inline]
    pub fn udp_ip(
        &mut self,
        src_ip:   Ipv4Addr,
        src_port: u16,
        dst_ip:   Ipv4Addr,
        dst_port: u16,
        payload:  &[u8]
        ) -> &[u8]
    {
        let len_payload: usize = payload.len().try_into().unwrap();
        let len_pkt:     usize = 28 + len_payload;
        
        self.buffer[28..len_pkt].copy_from_slice(&payload);

        HeaderBuilder::udp(
            &mut self.buffer[20..len_pkt],
            src_ip, src_port,
            dst_ip, dst_port, len_payload as u16
        );
        
        HeaderBuilder::ip(&mut self.buffer[..20], len_pkt as u16, 17, src_ip, dst_ip);

        &self.buffer[..len_pkt]
    }



    #[inline]
    pub fn icmp_ping(
        &mut self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        ) -> &[u8]
    {
        HeaderBuilder::icmp(&mut self.buffer[20..28]);
        HeaderBuilder::ip(&mut self.buffer[..20], 28, 1, src_ip, dst_ip);

        &self.buffer[..28]
    }



    #[inline]
    pub fn tcp_over_udp(
        &mut self,
        src_mac:      [u8; 6],
        src_ip:       Ipv4Addr,
        src_udp_port: u16,
        src_tcp_port: u16,
        dst_mac:      [u8; 6],
        dst_ip:       Ipv4Addr,
        dst_udp_port: u16,
        dst_tcp_port: u16
        ) -> &[u8]
    {
        HeaderBuilder::tcp(&mut self.buffer[42..69], src_ip, src_tcp_port, dst_ip, dst_tcp_port);
        HeaderBuilder::udp(&mut self.buffer[34..42], src_ip, src_udp_port, dst_ip, dst_udp_port, 0);
        HeaderBuilder::ip(&mut self.buffer[14..34], 40, 17, src_ip, dst_ip);
        HeaderBuilder::ether(&mut self.buffer[..14], src_mac, dst_mac);

        &self.buffer[..69]
    }



    #[inline]
    pub fn tcp_ether(
        &mut self,
        src_mac:  [u8; 6],
        src_ip:   Ipv4Addr,
        src_port: u16,
        dst_mac:  [u8; 6],
        dst_ip:   Ipv4Addr,
        dst_port: u16,
        ) -> &[u8]
    {
        HeaderBuilder::tcp(&mut self.buffer[34..54], src_ip, src_port, dst_ip, dst_port);
        HeaderBuilder::ip(&mut self.buffer[14..34], 40, 6, src_ip, dst_ip);
        HeaderBuilder::ether(&mut self.buffer[..14], src_mac, dst_mac);
        
        &self.buffer[..54]
    }



    #[inline]
    pub fn udp_ether(
        &mut self,
        src_mac:  [u8; 6],
        src_ip:   Ipv4Addr,
        src_port: u16,
        dst_mac:  [u8; 6],
        dst_ip:   Ipv4Addr,
        dst_port: u16,
        ) -> &[u8]
    {
        HeaderBuilder::udp(&mut self.buffer[34..42], src_ip, src_port, dst_ip, dst_port, 0);
        HeaderBuilder::ip(&mut self.buffer[14..34], 28, 17, src_ip, dst_ip);
        HeaderBuilder::ether(&mut self.buffer[..14], src_mac, dst_mac);

        &self.buffer[..42]
    }



    #[inline]
    pub fn icmp_ping_ether(
        &mut self,
        src_mac: [u8; 6],
        src_ip:  Ipv4Addr,
        dst_mac: [u8; 6],
        dst_ip:  Ipv4Addr,
        ) -> &[u8]
    {
        HeaderBuilder::icmp(&mut self.buffer[34..42]);
        HeaderBuilder::ip(&mut self.buffer[14..34], 28, 1, src_ip, dst_ip);
        HeaderBuilder::ether(&mut self.buffer[..14], src_mac, dst_mac);

        &self.buffer[..42]
    }



    #[inline]
    pub fn auth_802_11(
        &mut self,
        src_mac: [u8; 6],
        dst_mac: [u8; 6]
        ) -> &[u8]
    {
        HeaderBuilder::auth_802_11(&mut self.buffer, src_mac, dst_mac);

        self.buffer[24..26].copy_from_slice(&0u16.to_le_bytes());
        self.buffer[26..28].copy_from_slice(&1u16.to_le_bytes());
        self.buffer[28..30].copy_from_slice(&0u16.to_le_bytes());
        &self.buffer[..30]
    }

}