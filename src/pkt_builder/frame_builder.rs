use crate::pkt_builder::{RadiotapHeader, Ieee80211Header};



pub struct FrameBuilder {
    buffer: [u8; 38],
}


impl FrameBuilder {

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
        RadiotapHeader::build_header(&mut self.buffer);
        Ieee80211Header::deauth(&mut self.buffer, src_mac, dst_mac, bssid, seq_num);

        &self.buffer[..38]
    }

    

    #[inline]
    pub fn auth(
        &mut self, 
        src_mac: [u8; 6], 
        dst_mac: [u8; 6]
    ) -> &[u8] 
    { 
        Ieee80211Header::auth(&mut self.buffer, src_mac, dst_mac);
        &self.buffer[..30]
    }

}