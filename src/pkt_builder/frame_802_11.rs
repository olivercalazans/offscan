pub struct Frame802_11 {
    buffer: [u8; 30],
}


impl Frame802_11 {

    pub fn new() -> Self {
        Self { buffer: [0; 30], }
    }



    #[inline]
    pub fn auth_802_11(
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