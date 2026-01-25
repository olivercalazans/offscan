use std::net::Ipv4Addr;
use crate::builders::packets::{ip_header, ether_header, Checksum};
use crate::addrs::Mac;



pub(super) struct IcmpPktBuilder;


impl IcmpPktBuilder {

    #[inline]
    fn header(
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
    pub fn icmp_ping(
        buffer : &mut [u8; 347],
        src_ip : Ipv4Addr,
        dst_ip : Ipv4Addr,
    ) 
      -> usize
    {
        Self::header(&mut buffer[20..28]);
        ip_header(&mut buffer[..20], 28, 1, src_ip, dst_ip);

        28
    }




    #[inline]
    pub fn icmp_ping_ether(
        buffer  : &mut [u8; 347],
        src_mac : Mac,
        src_ip  : Ipv4Addr,
        dst_mac : Mac,
        dst_ip  : Ipv4Addr,
    ) 
      -> usize
    {
        Self::header(&mut buffer[34..42]);
        ip_header(&mut buffer[14..34], 28, 1, src_ip, dst_ip);
        ether_header(&mut buffer[..14], src_mac, dst_mac);

        42
    }

}