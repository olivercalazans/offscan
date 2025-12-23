pub struct Frame802_11 {
    buffer: [u8; 30],
}


impl Frame802_11 {

    pub fn new() -> Self {
        Self { buffer: [0; 30], }
    }


    
    #[inline]
    pub fn deauth(
        &mut self,
        src_mac:     [u8; 6],
        dst_mac:     [u8; 6],
        bssid:       [u8; 6],
        reason_code: u16
        ) -> &[u8]
    {
        self.buffer[0] = 0xC0;
        self.buffer[1] = 0x00;
        self.buffer[2] = 0x00;
        self.buffer[3] = 0x00;
        self.buffer[4..10].copy_from_slice(&dst_mac);
        self.buffer[10..16].copy_from_slice(&src_mac);
        self.buffer[16..22].copy_from_slice(&bssid);
        self.buffer[22] = 0x00;
        self.buffer[23] = 0x00;
        self.buffer[24] = reason_code as u8;
        self.buffer[25] = (reason_code >> 8) as u8;
        
        &self.buffer[..26]
    }



    #[inline]
    pub fn auth(
        &mut self,
        src_mac: [u8; 6],
        dst_mac: [u8; 6]
        ) -> &[u8]
    {
        let frame_control: u16 = (0u16)
            | (0u16  << 2)
            | (11u16 << 4)
            | (1u16  << 8)
            | (0u16  << 9);

        self.buffer[..2].copy_from_slice(&frame_control.to_le_bytes());        
        self.buffer[2..4].copy_from_slice(&0u16.to_le_bytes());        
        self.buffer[4..10].copy_from_slice(&dst_mac);
        self.buffer[10..16].copy_from_slice(&src_mac);
        self.buffer[16..22].copy_from_slice(&dst_mac);
        self.buffer[22..24].copy_from_slice(&0u16.to_le_bytes());

        self.buffer[24..26].copy_from_slice(&0u16.to_le_bytes());
        self.buffer[26..28].copy_from_slice(&1u16.to_le_bytes());
        self.buffer[28..].copy_from_slice(&0u16.to_le_bytes());
        &self.buffer
    }

}