use crate::utils::Mac;



#[inline]
pub(super) fn ether_header(
    buffer  : &mut [u8],
    src_mac : Mac,
    dst_mac : Mac
) {
    buffer[0..6].copy_from_slice(dst_mac.bytes());
    buffer[6..12].copy_from_slice(src_mac.bytes());
    buffer[12..].copy_from_slice(&0x0800u16.to_be_bytes());
}