use std::{thread, time::Duration, collections::{HashSet, BTreeMap}, mem};
use crate::arg_parser::WmapArgs;
use crate::dissectors::BeaconDissector;
use crate::iface::InterfaceManager;
use crate::sniffer::PacketSniffer;



#[derive(Debug)]
struct Info {
    macs:    HashSet<String>,
    channel: String,
}


impl Info {
    fn new(mac: String, channel: String) -> Self {
        let mut macs = HashSet::new();
        macs.insert(mac);

        Self { macs, channel }
    }
}



pub struct WifiMapper {
    args:        WmapArgs,
    raw_beacons: Vec<Vec<u8>>,
    wifis:       BTreeMap<String, Info>,
}


impl WifiMapper {
    
    pub fn new(args: WmapArgs) -> Self {
        Self {
            raw_beacons: Vec::new(),
            wifis:       BTreeMap::new(),
            args,
        }
    }



    pub fn execute(&mut self) {
        self.get_beacons();
        self.process_beacons();
        self.display_results();
    }
    


    fn get_beacons(&mut self) {
        InterfaceManager::enable_monitor_mode(&self.args.iface);
        
        let mut sniffer = PacketSniffer::new(
            self.args.iface.clone(),
            "type mgt and subtype beacon".to_string()
        );

        println!("Sniffing beacons");
        
        sniffer.start();
        thread::sleep(Duration::from_secs(self.args.time));
        sniffer.stop();

        InterfaceManager::disable_monitor_mode(&self.args.iface);

        self.raw_beacons = sniffer.get_packets();
    }



    fn process_beacons(&mut self) {
        let beacons = mem::take(&mut self.raw_beacons);

        for b in beacons.into_iter() {
            if let Some(info) = BeaconDissector::parse_beacon(&b) {
                self.add_info(info);
            }
        }
    }



    fn add_info(&mut self, info: Vec<String>) {
        let ssid    = info[0].clone();
        let mac     = info[1].clone();
        let channel = info[2].clone();

        self.wifis
            .entry(ssid)
            .and_modify(|existing_info| {
                existing_info.macs.insert(mac.clone());
            })
            .or_insert_with(|| {
                Info::new(mac, channel)
            });
    }



    fn display_results(&mut self) {
        let max_len = self.wifis.keys().map(String::len).max().unwrap_or(4);
        let wifis   = mem::take(&mut self.wifis);

        Self::display_header(max_len);
        
        for (name, info) in wifis.into_iter() {
            Self::display_wifi_info(&name, &info, max_len);
        }
    }



    fn display_header(max_len: usize) {
        println!("\n{:<width$}  {:<17}  {}", "SSID", "MAC", "Channel", width = max_len);
        Self::display_line(max_len);
    }



    fn display_line(max_len: usize) {
        println!("{}  {}  {}", "-".repeat(max_len), "-".repeat(17), "-".repeat(7));
    }



    fn display_wifi_info(name: &str, info: &Info, max_len: usize) {
        let macs: Vec<&String> = info.macs.iter().collect();

        Self::display_line(max_len);
        
        println!("{:<width$}  {}  {}",
                 name, 
                 macs.first().unwrap_or(&&"N/A".to_string()), 
                 info.channel,
                 width = max_len);
        
        for mac in macs.iter().skip(1) {
            println!("{:<width$}  {}",
                     "",
                     mac,
                     width = max_len);
        }
    }

}