use std::net::Ipv4Addr;
use crate::pkt_builder::HeaderBuilder;



pub struct PacketBuilder {
    packet: [u8; 301],
    layer4: [u8; 267],
    ip:     [u8; 20],
    ether:  [u8; 14],
}



impl PacketBuilder {

    pub fn new() -> Self {
        Self {
            packet: [0; 301],
            layer4: [0; 267],
            ip:     [0; 20],
            ether:  [0; 14],
        }
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
        HeaderBuilder::tcp(&mut self.layer4, src_ip, src_port, dst_ip, dst_port);
        HeaderBuilder::ip(&mut self.ip, 40, 6, src_ip, dst_ip);
        
        self.packet[..20].copy_from_slice(&self.ip);
        self.packet[20..40].copy_from_slice(&self.layer4[..20]);
        &self.packet[..40]
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
        let len_udp: usize     = 8 + len_payload;
        let len_pkt: usize     = 20 + len_udp;
        
        self.layer4[8..len_udp].copy_from_slice(&payload);

        HeaderBuilder::udp(&mut self.layer4, src_ip, src_port, dst_ip, dst_port, len_payload as u16);
        HeaderBuilder::ip(&mut self.ip, len_pkt as u16, 17, src_ip, dst_ip);

        self.packet[..20].copy_from_slice(&self.ip);
        self.packet[20..len_pkt].copy_from_slice(&self.layer4[..len_udp]);
        &self.packet[..len_pkt]
    }



    #[inline]
    pub fn icmp_ping(
        &mut self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        ) -> &[u8]
    {
        HeaderBuilder::icmp(&mut self.layer4);
        HeaderBuilder::ip(&mut self.ip, 28, 1, src_ip, dst_ip);

        self.packet[..20].copy_from_slice(&self.ip);
        self.packet[20..28].copy_from_slice(&self.layer4[..8]);
        &self.packet[..28]
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
        let mut tcp_buffer = [0u8; 27];        

        HeaderBuilder::tcp(&mut tcp_buffer, src_ip, src_tcp_port, dst_ip, dst_tcp_port);
        HeaderBuilder::udp(&mut self.layer4, src_ip, src_udp_port, dst_ip, dst_udp_port, 0);
        HeaderBuilder::ip(&mut self.ip, 40, 17, src_ip, dst_ip);
        HeaderBuilder::ether(&mut self.ether, src_mac, dst_mac);

        self.packet[..14].copy_from_slice(&self.ether);
        self.packet[14..34].copy_from_slice(&self.ip);
        self.packet[34..42].copy_from_slice(&self.layer4[..8]);
        self.packet[42..69].copy_from_slice(&tcp_buffer);
        &self.packet[..69]
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
        HeaderBuilder::tcp(&mut self.layer4, src_ip, src_port, dst_ip, dst_port);
        HeaderBuilder::ip(&mut self.ip, 40, 6, src_ip, dst_ip);
        HeaderBuilder::ether(&mut self.ether, src_mac, dst_mac);
        
        self.packet[..14].copy_from_slice(&self.ether);
        self.packet[14..34].copy_from_slice(&self.ip);
        self.packet[34..54].copy_from_slice(&self.layer4[..20]);
        &self.packet[..54]
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
        HeaderBuilder::udp(&mut self.layer4, src_ip, src_port, dst_ip, dst_port, 0);
        HeaderBuilder::ip(&mut self.ip, 28, 17, src_ip, dst_ip);
        HeaderBuilder::ether(&mut self.ether, src_mac, dst_mac);

        self.packet[..14].copy_from_slice(&self.ether);
        self.packet[14..34].copy_from_slice(&self.ip);
        self.packet[34..42].copy_from_slice(&self.layer4[..8]);
        &self.packet[..42]
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
        HeaderBuilder::icmp(&mut self.layer4);
        HeaderBuilder::ip(&mut self.ip, 28, 1, src_ip, dst_ip);
        HeaderBuilder::ether(&mut self.ether, src_mac, dst_mac);

        self.packet[..14].copy_from_slice(&self.ether);
        self.packet[14..34].copy_from_slice(&self.ip);
        self.packet[34..42].copy_from_slice(&self.layer4[..8]);
        &self.packet[..42]
    }



    #[inline]
    pub fn auth_802_11(
        &mut self,
        src_mac: [u8; 6],
        dst_mac: [u8; 6]
        ) -> &[u8]
    {
        HeaderBuilder::auth_802_11(&mut self.packet, src_mac, dst_mac);

        self.packet[24..26].copy_from_slice(&0u16.to_le_bytes());
        self.packet[26..28].copy_from_slice(&1u16.to_le_bytes());
        self.packet[28..30].copy_from_slice(&0u16.to_le_bytes());
        &self.packet[..30]
    }

}