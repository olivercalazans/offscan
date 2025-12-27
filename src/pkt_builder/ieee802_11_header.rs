pub struct Ieee80211Header;


impl Ieee80211Header {
    
    #[inline]
    pub fn deauth(
        buffer  : &mut [u8],
        src_mac : [u8; 6],
        dst_mac : [u8; 6], 
        bssid   : [u8; 6],
        seq_num : u16,
    ) {
        buffer[12] = 0xC0;
        buffer[13] = 0x00;
        buffer[14] = 0x3a;
        buffer[15] = 0x01;

        buffer[16..22].copy_from_slice(&dst_mac);
        buffer[22..28].copy_from_slice(&src_mac);
        buffer[28..34].copy_from_slice(&bssid);

        let seq_control = ((seq_num & 0x0FFF) << 4) | 0x00;
        buffer[34..36].copy_from_slice(&seq_control.to_le_bytes());
        
        buffer[36] = 0x0007;
        buffer[37] = 0x00;
    }

}