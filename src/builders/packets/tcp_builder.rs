use std::net::Ipv4Addr;
use crate::builders::packets::{ip_header, ether_header, Checksum};
use crate::utils::Mac;



pub(super) struct TcpPktBuilder;


impl TcpPktBuilder {

    #[inline]
    fn header(
        buffer   : &mut [u8],
        src_ip   : Ipv4Addr,
        src_port : u16, 
        dst_ip   : Ipv4Addr,
        dst_port : u16,
        flag     : &str,
    ) {
        let bflag = if flag == "syn" {0x02} else {0x10};

        buffer[..2].copy_from_slice(&src_port.to_be_bytes());
        buffer[2..4].copy_from_slice(&dst_port.to_be_bytes());
        buffer[4..8].copy_from_slice(&1u32.to_be_bytes());
        buffer[8..12].copy_from_slice(&0u32.to_be_bytes());
        buffer[12] = 5 << 4;
        buffer[13] = bflag;
        buffer[14..16].copy_from_slice(&64240u16.to_be_bytes());
        buffer[16..18].copy_from_slice(&0u16.to_be_bytes());
        buffer[18..20].copy_from_slice(&0u16.to_be_bytes());

        let cksum = Checksum::tcp_udp_checksum(&buffer[..20], &src_ip, &dst_ip, 6);
        buffer[16..18].copy_from_slice(&cksum.to_be_bytes());
    }



    #[inline]
    pub fn tcp_ip(
        buffer   : &mut [u8; 347],
        src_ip   : Ipv4Addr,
        src_port : u16,
        dst_ip   : Ipv4Addr,
        dst_port : u16,
    ) 
      -> usize 
    {
        Self::header(&mut buffer[20..40], src_ip, src_port, dst_ip, dst_port, "syn");
        ip_header(&mut buffer[..20], 40, 6, src_ip, dst_ip);
        
        40
    }



    #[inline]
    pub fn tcp_ether(
        buffer   : &mut [u8; 347],
        src_mac  : Mac,
        src_ip   : Ipv4Addr,
        src_port : u16,
        dst_mac  : Mac,
        dst_ip   : Ipv4Addr,
        dst_port : u16,
        flag     : &str,
    ) 
      -> usize
    {
        Self::header(&mut buffer[34..54], src_ip, src_port, dst_ip, dst_port, flag);
        ip_header(&mut buffer[14..34], 40, 6, src_ip, dst_ip);
        ether_header(&mut buffer[..14], src_mac, dst_mac);
        
        54
    }
    
}