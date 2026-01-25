use std::collections::HashSet;
use crate::addrs::Bssid;



pub(super) struct WifiData {
    pub bssids : HashSet<Bssid>,
    pub chnl   : u8,
    pub freq   : String,
    pub sec    : String,
}


impl WifiData {
    pub fn new(
        bssid : Bssid, 
        chnl  : u8, 
        freq  : String,
        sec   : String,
    ) -> Self 
    {
        let mut bssids = HashSet::new();
        bssids.insert(bssid);

        Self { bssids, chnl, freq, sec }
    }
}