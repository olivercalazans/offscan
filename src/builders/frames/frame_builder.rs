use crate::builders::frames::{Radiotap, Ieee80211};



pub struct Frames {
    buffer: [u8; 38],
}


impl Frames {

    pub fn new() -> Self {
        Self { buffer: [0; 38], }
    }



    #[inline]
    pub fn deauth(
        &mut self,
        src_mac : [u8; 6],
        dst_mac : [u8; 6], 
        bssid   : [u8; 6],
        seq_num : u16,
    ) -> &[u8] 
    {
        Radiotap::build_header(&mut self.buffer[..12]);
        Ieee80211::deauth(&mut self.buffer[12..38], src_mac, dst_mac, bssid, seq_num);

        &self.buffer[..38]
    }

}