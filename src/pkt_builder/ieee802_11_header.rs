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



    #[inline]
    pub fn auth(
        buffer  : &mut [u8],
        src_mac : [u8; 6],
        dst_mac : [u8; 6]
    ) {
        let frame_control: u16 = (0u16)
            | (0u16  << 2)
            | (11u16 << 4)
            | (1u16  << 8)
            | (0u16  << 9);

        buffer[..2].copy_from_slice(&frame_control.to_le_bytes());        
        buffer[2..4].copy_from_slice(&0u16.to_le_bytes());        
        buffer[4..10].copy_from_slice(&dst_mac);
        buffer[10..16].copy_from_slice(&src_mac);
        buffer[16..22].copy_from_slice(&dst_mac);
        buffer[22..24].copy_from_slice(&0u16.to_le_bytes());

        buffer[24..26].copy_from_slice(&0u16.to_le_bytes());
        buffer[26..28].copy_from_slice(&1u16.to_le_bytes());
        buffer[28..30].copy_from_slice(&0u16.to_le_bytes());
    }

}