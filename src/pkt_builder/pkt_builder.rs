use std::net::Ipv4Addr;
use crate::pkt_builder::{PacketBuffer, HeaderBuilder};



pub struct PacketBuilder {
    pkt_buf: PacketBuffer,
}



impl PacketBuilder {

    pub fn new() -> Self {
        Self { pkt_buf: PacketBuffer::default() }
    }



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
        HeaderBuilder::udp(&mut self.pkt_buf.layer4, src_ip, src_udp_port, dst_ip, dst_udp_port, 0);
        HeaderBuilder::ip(&mut self.pkt_buf.ip, 40, 17, src_ip, dst_ip);
        HeaderBuilder::ether(&mut self.pkt_buf.ether, src_mac, dst_mac);

        self.pkt_buf.packet[..14].copy_from_slice(&self.pkt_buf.ether);
        self.pkt_buf.packet[14..34].copy_from_slice(&self.pkt_buf.ip);
        self.pkt_buf.packet[34..42].copy_from_slice(&self.pkt_buf.layer4[..8]);
        self.pkt_buf.packet[42..].copy_from_slice(&tcp_buffer);
        &self.pkt_buf.packet
    }



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
        HeaderBuilder::tcp(&mut self.pkt_buf.layer4, src_ip, src_port, dst_ip, dst_port);
        HeaderBuilder::ip(&mut self.pkt_buf.ip, 40, 6, src_ip, dst_ip);
        HeaderBuilder::ether(&mut self.pkt_buf.ether, src_mac, dst_mac);
        
        self.pkt_buf.packet[..14].copy_from_slice(&self.pkt_buf.ether);
        self.pkt_buf.packet[14..34].copy_from_slice(&self.pkt_buf.ip);
        self.pkt_buf.packet[34..54].copy_from_slice(&self.pkt_buf.layer4);
        &self.pkt_buf.packet[..54]
    }



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
        HeaderBuilder::udp(&mut self.pkt_buf.layer4, src_ip, src_port, dst_ip, dst_port, 0);
        HeaderBuilder::ip(&mut self.pkt_buf.ip, 28, 17, src_ip, dst_ip);
        HeaderBuilder::ether(&mut self.pkt_buf.ether, src_mac, dst_mac);

        self.pkt_buf.packet[..14].copy_from_slice(&self.pkt_buf.ether);
        self.pkt_buf.packet[14..34].copy_from_slice(&self.pkt_buf.ip);
        self.pkt_buf.packet[34..42].copy_from_slice(&self.pkt_buf.layer4[..8]);
        &self.pkt_buf.packet[..42]
    }



    pub fn tcp_ip(
        &mut self,
        src_ip:   Ipv4Addr,
        src_port: u16,
        dst_ip:   Ipv4Addr,
        dst_port: u16,
        ) -> &[u8]
    {
        HeaderBuilder::tcp(&mut self.pkt_buf.layer4, src_ip, src_port, dst_ip, dst_port);
        HeaderBuilder::ip(&mut self.pkt_buf.ip, 40, 6, src_ip, dst_ip);
        
        self.pkt_buf.packet[..20].copy_from_slice(&self.pkt_buf.ip);
        self.pkt_buf.packet[20..40].copy_from_slice(&self.pkt_buf.layer4);
        &self.pkt_buf.packet[..40]
    }



    pub fn udp_ip(
        &mut self,
        src_ip:   Ipv4Addr,
        src_port: u16,
        dst_ip:   Ipv4Addr,
        dst_port: u16,
        ) -> &[u8]
    {
        HeaderBuilder::udp(&mut self.pkt_buf.layer4, src_ip, src_port, dst_ip, dst_port, 0);
        HeaderBuilder::ip(&mut self.pkt_buf.ip, 28, 17, src_ip, dst_ip);

        self.pkt_buf.packet[..20].copy_from_slice(&self.pkt_buf.ip);
        self.pkt_buf.packet[20..28].copy_from_slice(&self.pkt_buf.layer4[..8]);
        &self.pkt_buf.packet[..28]
    }



    pub fn icmp_echo_req(
        &mut self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        ) -> &[u8]
    {
        HeaderBuilder::icmp(&mut self.pkt_buf.layer4);
        HeaderBuilder::ip(&mut self.pkt_buf.ip, 28, 1, src_ip, dst_ip);

        self.pkt_buf.packet[..20].copy_from_slice(&self.pkt_buf.ip);
        self.pkt_buf.packet[20..28].copy_from_slice(&self.pkt_buf.layer4[..8]);
        &self.pkt_buf.packet[..28]
    }



    pub fn auth_802_11(
        &mut self,
        src_mac: [u8; 6],
        dst_mac: [u8; 6]
        ) -> &[u8]
    {
        HeaderBuilder::auth_802_11(&mut self.pkt_buf.packet, src_mac, dst_mac);

        self.pkt_buf.packet[24..26].copy_from_slice(&0u16.to_le_bytes());
        self.pkt_buf.packet[26..28].copy_from_slice(&1u16.to_le_bytes());
        self.pkt_buf.packet[28..30].copy_from_slice(&0u16.to_le_bytes());
        &self.pkt_buf.packet[..30]
    }

}