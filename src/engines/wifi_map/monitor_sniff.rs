use std::{thread, time::Duration, collections::BTreeMap};
use crate::engines::wifi_map::WifiData;
use crate::dissectors::BeaconDissector;
use crate::iface::IfaceManager;
use crate::sniffer::Sniffer;
use crate::utils::inline_display;



pub struct MonitorSniff<'a> {
    iface     : String,
    wifis_buf : &'a mut BTreeMap<String, WifiData>,
}


impl<'a> MonitorSniff<'a> {

    pub fn new(
        iface     : String, 
        wifis_buf : &'a mut BTreeMap<String, WifiData>
    ) -> Self {
        Self { iface, wifis_buf, }
    }



    pub fn execute_monitor_sniff(&mut self) {
        println!("Sniffing beacons on monitor mode");

        let beacons = self.start_sniffing();
        self.process_beacons(beacons);
    }



    fn start_sniffing(&mut self) -> Vec<Vec<u8>> {
        let mut sniffer = Sniffer::new(
            self.iface.clone(),
            "type mgt and subtype beacon".to_string()
        );
        
        sniffer.start();
        self.sniff_2g_channels();
        self.sniff_5g_channels();
        sniffer.stop();

        sniffer.get_packets()
    }    



    fn sniff_2g_channels(&self) {
        let channels: Vec<i32> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        self.sniff_channels(channels, "2.4");
    }



    fn sniff_5g_channels(&self) {
        let channels: Vec<i32> = vec![
            36,  40,  44,  48,  52,  56,  60,  64,  100, 104,
            108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
            149, 153, 157, 161, 165
        ];

        self.sniff_channels(channels, "5");
    }



    #[inline]
    fn sniff_channels(&self, channels: Vec<i32>, frequency: &str) {
        let mut err: Vec<i32> = Vec::new();

        for channel in channels {
            let done = IfaceManager::set_channel(&self.iface, channel);

            if !done {
                err.push(channel);
                continue;
            }

            inline_display(&format!("Sniffing channel {} ({}G)", channel, frequency));
            thread::sleep(Duration::from_millis(300));
        }

        if err.len() > 0 {
            println!("[!] Uneable to sniff these channels ({}G):\n{:?}", frequency, err);
        }
    }



    fn process_beacons(&mut self, beacons: Vec<Vec<u8>>) {
        for b in beacons.into_iter() {
            if let Some(info) = BeaconDissector::parse_beacon(&b) {
                let ssid        = info[0].clone();
                let bssid       = info[1].clone();
                let channel: u8 = info[2].parse().unwrap_or_else(|_| 0);
                let frequency   = Self::get_frequency(channel);
                
                self.add_info(ssid, bssid, channel, frequency);
            }
        }
    }



    fn get_frequency(channel: u8) -> String {
        if channel <= 14 {"2.4".to_string()} else {"5".to_string()}
    }



    #[inline]
    fn add_info(
        &mut self, 
        ssid      : String, 
        bssid     : String, 
        channel   : u8, 
        frequency : String
    ) {
        self.wifis_buf
            .entry(ssid)
            .and_modify(|existing_info| {
                existing_info.bssids.insert(bssid.clone());
            })
            .or_insert_with(|| {
                WifiData::new(bssid, channel, frequency.to_string())
            });
    }

}