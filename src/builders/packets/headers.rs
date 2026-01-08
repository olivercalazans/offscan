use std::net::Ipv4Addr;
use crate::builders::packets::Checksum;



pub(super) struct Headers;


impl Headers {


    #[inline]
    pub fn tcp(
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
    pub fn udp(
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
    pub fn icmp(
        buffer: &mut [u8]
    ) {
        buffer[0] = 8;
        buffer[1] = 0;
        buffer[2..4].copy_from_slice(&0u16.to_be_bytes());
        buffer[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); 
        buffer[6..8].copy_from_slice(&1u16.to_be_bytes());

        let cksum = Checksum::icmp_checksum(&buffer[..8]);
        buffer[2..4].copy_from_slice(&cksum.to_be_bytes());
    }



    #[inline]
    pub fn ip(
        buffer   : &mut [u8],
        len      : u16,
        protocol : u8,
        src_ip   : Ipv4Addr,
        dst_ip   : Ipv4Addr
    ) {
        buffer[0] = (4 << 4) | 5;
        buffer[1] = 0;
        buffer[2..4].copy_from_slice(&len.to_be_bytes());
        buffer[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        buffer[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        buffer[8] = 64;
        buffer[9] = protocol;
        buffer[10..12].copy_from_slice(&0u16.to_be_bytes());
        buffer[12..16].copy_from_slice(&src_ip.octets());
        buffer[16..20].copy_from_slice(&dst_ip.octets());

        let cksum = Checksum::ipv4_checksum(&buffer);
        buffer[10..12].copy_from_slice(&cksum.to_be_bytes());
    }



    #[inline]
    pub fn ether(
        buffer  : &mut [u8],
        src_mac : [u8; 6],
        dst_mac : [u8; 6]
    ) {
        buffer[0..6].copy_from_slice(&dst_mac);
        buffer[6..12].copy_from_slice(&src_mac);
        buffer[12..].copy_from_slice(&0x0800u16.to_be_bytes());
    }

}