use std::net::Ipv4Addr;
use crate::pkt_builder::HeaderBuilder;



pub struct TcpPacket;


impl TcpPacket {

    #[inline]
    pub fn tcp_ip(
        buffer   : &mut [u8; 347],
        src_ip   : Ipv4Addr,
        src_port : u16,
        dst_ip   : Ipv4Addr,
        dst_port : u16,
    ) -> usize 
    {
        HeaderBuilder::tcp(&mut buffer[20..40], src_ip, src_port, dst_ip, dst_port, "syn");
        HeaderBuilder::ip(&mut buffer[..20], 40, 6, src_ip, dst_ip);
        
        40
    }



    #[inline]
    pub fn tcp_ether(
        buffer   : &mut [u8; 347],
        src_mac  : [u8; 6],
        src_ip   : Ipv4Addr,
        src_port : u16,
        dst_mac  : [u8; 6],
        dst_ip   : Ipv4Addr,
        dst_port : u16,
        flag     : &str,
    ) -> usize
    {
        HeaderBuilder::tcp(&mut buffer[34..54], src_ip, src_port, dst_ip, dst_port, flag);
        HeaderBuilder::ip(&mut buffer[14..34], 40, 6, src_ip, dst_ip);
        HeaderBuilder::ether(&mut buffer[..14], src_mac, dst_mac);
        
        54
    }

}