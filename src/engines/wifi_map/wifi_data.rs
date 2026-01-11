use std::collections::HashSet;



pub(super) struct WifiData {
    pub bssids  : HashSet<String>,
    pub chnl : u8,
    pub freq    : String,
    pub sec     : String,
}


impl WifiData {
    pub fn new(
        bssid : String, 
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