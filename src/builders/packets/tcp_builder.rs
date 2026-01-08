use std::net::Ipv4Addr;
use crate::builders::packets::Headers;



pub(super) struct TcpPktBuilder;


impl TcpPktBuilder {

    #[inline]
    pub fn tcp_ip(
        buffer   : &mut [u8; 347],
        src_ip   : Ipv4Addr,
        src_port : u16,
        dst_ip   : Ipv4Addr,
        dst_port : u16,
    ) -> usize 
    {
        Headers::tcp(&mut buffer[20..40], src_ip, src_port, dst_ip, dst_port, "syn");
        Headers::ip(&mut buffer[..20], 40, 6, src_ip, dst_ip);
        
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
        Headers::tcp(&mut buffer[34..54], src_ip, src_port, dst_ip, dst_port, flag);
        Headers::ip(&mut buffer[14..34], 40, 6, src_ip, dst_ip);
        Headers::ether(&mut buffer[..14], src_mac, dst_mac);
        
        54
    }
    
}