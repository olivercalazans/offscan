use std::net::Ipv4Addr;
use crate::builders::packets::Headers;



pub struct IcmpPktBuilder;


impl IcmpPktBuilder {

     #[inline]
    pub fn icmp_ping(
        buffer : &mut [u8; 347],
        src_ip : Ipv4Addr,
        dst_ip : Ipv4Addr,
    ) -> usize
    {
        Headers::icmp(&mut buffer[20..28]);
        Headers::ip(&mut buffer[..20], 28, 1, src_ip, dst_ip);

        28
    }




    #[inline]
    pub fn icmp_ping_ether(
        buffer  : &mut [u8; 347],
        src_mac : [u8; 6],
        src_ip  : Ipv4Addr,
        dst_mac : [u8; 6],
        dst_ip  : Ipv4Addr,
    ) -> usize
    {
        Headers::icmp(&mut buffer[34..42]);
        Headers::ip(&mut buffer[14..34], 28, 1, src_ip, dst_ip);
        Headers::ether(&mut buffer[..14], src_mac, dst_mac);

        42
    }

}