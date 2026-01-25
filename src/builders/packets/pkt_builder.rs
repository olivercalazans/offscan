use std::net::Ipv4Addr;
use crate::addrs::Mac;
use crate::builders::packets::{IcmpPktBuilder, TcpPktBuilder, UdpPktBuilder};



pub(crate) struct Packets {
    buffer: [u8; 347],
}


impl Packets {

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
    ) 
      -> &[u8]
    {
        let pkt_len = TcpPktBuilder::tcp_ip(
            &mut self.buffer, 
            src_ip, src_port, 
            dst_ip, dst_port
        );

        &self.buffer[..pkt_len]
    }



    #[inline]
    pub fn tcp_ether(
        &mut self,
        src_mac  : Mac,
        src_ip   : Ipv4Addr,
        src_port : u16,
        dst_mac  : Mac,
        dst_ip   : Ipv4Addr,
        dst_port : u16,
        flag     : &str,
    ) 
      -> &[u8]
    {
        let pkt_len = TcpPktBuilder::tcp_ether(
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
    ) 
      -> &[u8]
    {
        let pkt_len = UdpPktBuilder::udp_ip(
            &mut self.buffer, 
            src_ip, src_port, 
            dst_ip, dst_port, 
            payload
        );

        &self.buffer[..pkt_len]
    }



    #[inline]
    pub fn icmp_ping(
        &mut self,
        src_ip : Ipv4Addr,
        dst_ip : Ipv4Addr,
    ) 
      -> &[u8]
    {
        let pkt_len = IcmpPktBuilder::icmp_ping(&mut self.buffer, src_ip, dst_ip);
        &self.buffer[..pkt_len]
    }



    #[inline]
    pub fn icmp_ping_ether(
        &mut self,
        src_mac : Mac,
        src_ip  : Ipv4Addr,
        dst_mac : Mac,
        dst_ip  : Ipv4Addr,
    ) 
      -> &[u8]
    {
        let pkt_len = IcmpPktBuilder::icmp_ping_ether(
            &mut self.buffer,
            src_mac, src_ip,
            dst_mac, dst_ip
        );

        &self.buffer[..pkt_len]
    }

}