use std::{thread, time::Duration, collections::{HashSet, BTreeMap}, mem};
use crate::engines::WmapArgs;
use crate::dissectors::BeaconDissector;
use crate::iface::IfaceManager;
use crate::sniffer::PacketSniffer;
use crate::utils::inline_display;




pub struct WifiMapper {
    args        : WmapArgs,
    raw_beacons : Vec<Vec<u8>>,
    wifis       : BTreeMap<String, Info>,
}


impl WifiMapper {
    
    pub fn new(args: WmapArgs) -> Self {
        Self {
            raw_beacons : Vec::new(),
            wifis       : BTreeMap::new(),
            args,
        }
    }



    pub fn execute(&mut self) {
        self.get_beacons();
        self.process_beacons();
        self.display_results();
    }
    


    fn get_beacons(&mut self) {        
        let mut sniffer = PacketSniffer::new(
            self.args.iface.clone(),
            "type mgt and subtype beacon".to_string()
        );

        println!("Sniffing beacons");
        
        sniffer.start();
        self.sniff_2g_channels();
        self.sniff_5g_channels();
        sniffer.stop();

        self.raw_beacons = sniffer.get_packets();
    }    



    fn sniff_2g_channels(&self) {
        const CHANNELS: [i32; 14] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];

        for channel in CHANNELS {
            self.set_channel(channel, "2.4");
        }
    }



    fn sniff_5g_channels(&self) {
        const CHANNELS: [i32; 25] = [
            36,  40,  44,  48,  52,  56,  60,  64,  100, 104,
            108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
            149, 153, 157, 161, 165
        ];


        for channel in CHANNELS {
            self.set_channel(channel, "5");
        }
    }



    #[inline]
    fn set_channel(&self, channel: i32, frequency: &str) {
        let done = IfaceManager::set_channel(&self.args.iface, channel);

        if !done {
            println!("Uneable to set channel {}", channel);
            return;
        }

        inline_display(&format!("Sniffing channel {} ({}G)", channel, frequency));
        thread::sleep(Duration::from_millis(300));
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
        let ssid         = info[0].clone();
        let mac          = info[1].clone();
        let channel: u32 = info[2].parse().unwrap_or_else(|_| 0);
        let frequency    = if channel <= 14 {"2.4"} else {"5"};

        self.wifis
            .entry(ssid)
            .and_modify(|existing_info| {
                existing_info.macs.insert(mac.clone());
            })
            .or_insert_with(|| {
                Info::new(mac, channel, frequency.to_string())
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
        println!(
            "\n{:<width$}  {:<17}  {}  {}", 
            "SSID", "MAC", "Channel", "Frequency", width = max_len
        );
        println!("{}  {}  {}  {}", "-".repeat(max_len), "-".repeat(17), "-".repeat(7), "-".repeat(9));
    }



    fn display_wifi_info(name: &str, info: &Info, max_len: usize) {
        let macs: Vec<&String> = info.macs.iter().collect();
        
        println!(
            "{:<width$}  {}  {:<7}  {}G",
            name, 
            macs.first().unwrap_or(&&"N/A".to_string()), 
            info.channel,
            info.frequency,
            width = max_len
        );
        
        for mac in macs.iter().skip(1) {
            println!("{:<width$}  {}", "", mac, width = max_len);
        }
    }

}



impl crate::EngineTrait for WifiMapper {
    type Args = WmapArgs;
    
    fn new(args: Self::Args) -> Self {
        WifiMapper::new(args)
    }
    
    fn execute(&mut self) {
        self.execute();
    }
}



#[derive(Debug)]
struct Info {
    macs      : HashSet<String>,
    channel   : u32,
    frequency : String
}


impl Info {
    fn new(
        mac       : String, 
        channel   : u32, 
        frequency : String
    ) -> Self {
        let mut macs = HashSet::new();
        macs.insert(mac);

        Self { macs, channel, frequency }
    }
}