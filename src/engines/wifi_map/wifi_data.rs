use std::collections::HashSet;



pub struct WifiData {
    pub bssids    : HashSet<String>,
    pub channel   : u8,
    pub frequency : String
}


impl WifiData {
    pub fn new(
        bssid     : String, 
        channel   : u8, 
        frequency : String
    ) -> Self {
        let mut bssids = HashSet::new();
        bssids.insert(bssid);

        Self { bssids, channel, frequency }
    }
}