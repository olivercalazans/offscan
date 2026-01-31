use crate::builders::ieee80211::Radiotap;
use crate::utils::{Bssid, Mac};



pub(crate) struct DeauthFrame {
    buffer: [u8; 38],
}


impl DeauthFrame {

    pub fn new(bssid: Bssid) -> Self {
        let buffer = Self::build_fixed(bssid);
        Self { buffer }
    }


    fn build_fixed(bssid: Bssid) -> [u8; 38] {
        let mut buffer = [0u8; 38];
        
        Radiotap::minimal_header(&mut buffer[..12]);

        buffer[12] = 0xC0;
        buffer[13] = 0x00;
        buffer[14] = 0x3a;
        buffer[15] = 0x01;

        buffer[28..34].copy_from_slice(bssid.bytes());

        buffer[36] = 0x07;
        buffer[37] = 0x00;

        buffer
    }



    #[inline]
    pub fn frame(
        &mut self,
        src_mac : Mac,
        dst_mac : Mac, 
        seq     : u16,
    ) 
      -> &[u8]
    {
        self.buffer[16..22].copy_from_slice(dst_mac.bytes());
        self.buffer[22..28].copy_from_slice(src_mac.bytes());

        let seq_ctrl = ((seq & 0x0FFF) << 4) | 0x00;
        self.buffer[34..36].copy_from_slice(&seq_ctrl.to_le_bytes());
        
        &self.buffer
    }

}