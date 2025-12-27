use std::net::Ipv4Addr;
use crate::pkt_builder::{IcmpPacket, TcpPacket, UdpPacket};



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
        src_ip   : Ipv4Addr,
        src_port : u16,
        dst_ip   : Ipv4Addr,
        dst_port : u16,
    ) -> &[u8]
    {
        let pkt_len = TcpPacket::tcp_ip(
            &mut self.buffer, 
            src_ip, src_port, 
            dst_ip, dst_port
        );

        &self.buffer[..pkt_len]
    }



    #[inline]
    pub fn tcp_ether(
        &mut self,
        src_mac  : [u8; 6],
        src_ip   : Ipv4Addr,
        src_port : u16,
        dst_mac  : [u8; 6],
        dst_ip   : Ipv4Addr,
        dst_port : u16,
        flag     : &str,
    ) -> &[u8]
    {
        let pkt_len = TcpPacket::tcp_ether(
            &mut self.buffer,
            src_mac, src_ip, src_port,
            dst_mac, dst_ip, dst_port,
            flag
        );

        &self.buffer[..pkt_len]
    }



    #[inline]
    pub fn udp_ip(
        &mut self,
        src_ip   : Ipv4Addr,
        src_port : u16,
        dst_ip   : Ipv4Addr,
        dst_port : u16,
        payload  : &[u8]
    ) -> &[u8]
    {
        let pkt_len = UdpPacket::udp_ip(
            &mut self.buffer, 
            src_ip, src_port, 
            dst_ip, dst_port, 
            payload
        );

        &self.buffer[..pkt_len]
    }



    #[inline]
    pub fn udp_ether(
        &mut self,
        src_mac  : [u8; 6],
        src_ip   : Ipv4Addr,
        src_port : u16,
        dst_mac  : [u8; 6],
        dst_ip   : Ipv4Addr,
        dst_port : u16,
        payload  : &[u8],
    ) -> &[u8]
    {
        let pkt_len = UdpPacket::udp_ether(
            &mut self.buffer,
            src_mac, src_ip, src_port,
            dst_mac, dst_ip, dst_port,
            payload
        );

        &self.buffer[..pkt_len]
    }



    #[inline]
    pub fn icmp_ping(
        &mut self,
        src_ip : Ipv4Addr,
        dst_ip : Ipv4Addr,
    ) -> &[u8]
    {
        let pkt_len = IcmpPacket::icmp_ping(&mut self.buffer, src_ip, dst_ip);
        &self.buffer[..pkt_len]
    }



    #[inline]
    pub fn icmp_ping_ether(
        &mut self,
        src_mac : [u8; 6],
        src_ip  : Ipv4Addr,
        dst_mac : [u8; 6],
        dst_ip  : Ipv4Addr,
    ) -> &[u8]
    {
        let pkt_len = IcmpPacket::icmp_ping_ether(
            &mut self.buffer,
            src_mac, src_ip,
            dst_mac, dst_ip
        );

        &self.buffer[..pkt_len]
    }

}