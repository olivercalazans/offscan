use crate::builders::frames::{Radiotap, Ieee80211};



pub(crate) struct Frames {
    buffer: [u8; 106],
}


impl Frames {

    pub fn new() -> Self {
        Self { buffer: [0; 106], }
    }



    #[inline]
    pub fn deauth(
        &mut self,
        src_mac : [u8; 6],
        dst_mac : [u8; 6], 
        bssid   : [u8; 6],
        seq     : u16,
    ) -> &[u8] 
    {
        Radiotap::minimal_header(&mut self.buffer[..12]);
        Ieee80211::deauth(&mut self.buffer[12..38], src_mac, dst_mac, bssid, seq);

        &self.buffer[..38]
    }



    #[inline]
    pub fn beacon(
        &mut self,
        bssid   : [u8; 6],
        ssid    : &str,
        seq     : u16,
        channel : u8,
    ) -> &[u8]
    {
        Radiotap::minimal_header(&mut self.buffer[..12]);
        Ieee80211::beacon_header(&mut self.buffer[12..36], bssid, seq);
        Ieee80211::beacon_body(&mut self.buffer[36..104], ssid, channel);

        &self.buffer[..104]
    }

}