pub(super) struct Ieee80211;


impl Ieee80211 {
    
    #[inline]
    pub fn deauth(
        buffer  : &mut [u8],
        src_mac : [u8; 6],
        dst_mac : [u8; 6], 
        bssid   : [u8; 6],
        seq_num : u16,
    ) {
        buffer[0] = 0xC0;
        buffer[1] = 0x00;
        buffer[2] = 0x3a;
        buffer[3] = 0x01;

        buffer[4..10].copy_from_slice(&dst_mac);
        buffer[10..16].copy_from_slice(&src_mac);
        buffer[16..22].copy_from_slice(&bssid);

        let seq_control = ((seq_num & 0x0FFF) << 4) | 0x00;
        buffer[22..24].copy_from_slice(&seq_control.to_le_bytes());
        
        buffer[24] = 0x0007;
        buffer[25] = 0x00;
    }
    

}