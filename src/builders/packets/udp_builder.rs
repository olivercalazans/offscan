use std::net::Ipv4Addr;
use crate::builders::packets::{ip_header, Checksum};



pub(super) struct UdpPktBuilder;


impl UdpPktBuilder {

    #[inline]
    fn header(
        buffer      : &mut [u8],
        src_ip      : Ipv4Addr,
        src_port    : u16,
        dst_ip      : Ipv4Addr,
        dst_port    : u16,
        len_payload : u16
    ) {
        let len = 8 + len_payload;

        buffer[..2].copy_from_slice(&src_port.to_be_bytes());
        buffer[2..4].copy_from_slice(&dst_port.to_be_bytes());
        buffer[4..6].copy_from_slice(&len.to_be_bytes());
        buffer[6..8].copy_from_slice(&0u16.to_be_bytes());
        
        let cksum = Checksum::tcp_udp_checksum(&buffer[..len as usize], &src_ip, &dst_ip, 17);
        buffer[6..8].copy_from_slice(&cksum.to_be_bytes());
    }



    #[inline]
    pub fn udp_ip(
        buffer   : &mut [u8; 347],
        src_ip   : Ipv4Addr,
        src_port : u16,
        dst_ip   : Ipv4Addr,
        dst_port : u16,
        payload  : &[u8]
    ) 
      -> usize 
    {
        let len_payload: usize = payload.len().try_into().unwrap();
        let len_pkt:     usize = 28 + len_payload;
        
        buffer[28..len_pkt].copy_from_slice(&payload);

        Self::header(
            &mut buffer[20..len_pkt],
            src_ip, src_port,
            dst_ip, dst_port, len_payload as u16
        );
        
        ip_header(&mut buffer[..20], len_pkt as u16, 17, src_ip, dst_ip);

        len_pkt
    }

}