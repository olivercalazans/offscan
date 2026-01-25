use std::net::Ipv4Addr;
use crate::builders::packets::Checksum;



#[inline]
pub(super) fn ip_header(
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