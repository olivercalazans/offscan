use std::{thread, time::Duration, collections::{HashSet, BTreeMap}, mem};
use crate::engines::WmapArgs;
use crate::dissectors::BeaconDissector;
use crate::iface::IfaceManager;
use crate::sniffer::PacketSniffer;
use crate::utils::{inline_display, mac_u8_to_string, abort};



#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct WifiInfo {
    bssid     : [u8; 6],
    ssid      : [i8; 33],
    frequency : u32,
}


unsafe extern "C" {
    fn scan_wifi(
        ifname  : *const i8,
        results : *mut *mut WifiInfo,
        count   : *mut i32,
    ) -> i32;

    fn free_scan_results(results: *mut WifiInfo);
}



pub struct WifiMapper {
    args  : WmapArgs,
    wifis : BTreeMap<String, Info>,
}


impl WifiMapper {
    
    pub fn new(args: WmapArgs) -> Self {
        Self { args, wifis : BTreeMap::new(), }
    }



    pub fn execute(&mut self) {
        match self.args.monitor {
            true  => self.sniff_beacons(),
            false => self.get_info_from_sys(),
        }

        self.display_results();
    }



    fn get_info_from_sys(&mut self) {
        println!("Sniffing beacons on monitor mode");

        let sys_info = self.call_c_module();
        self.process_info(sys_info);
    }



    fn call_c_module(&mut self) -> Vec<WifiInfo>{
        unsafe {
            let iface = std::ffi::CString::new(self.args.iface.clone()).unwrap();

            let mut ptr: *mut WifiInfo = std::ptr::null_mut();
            let mut count: i32 = 0;

            let ret = scan_wifi(
                iface.as_ptr(),
                &mut ptr,
                &mut count,
            );

            if ret != 0 {
                abort(format!("Erro no scan: {}", ret));
            }

            let slice    = std::slice::from_raw_parts(ptr, count as usize);
            let sys_info = slice.iter().copied().map(Into::into).collect();

            free_scan_results(ptr);

            sys_info
        }
    }



    fn process_info(&mut self, sys_info: Vec<WifiInfo>) {
        for info in sys_info.into_iter() {
            let ssid      = Self::ssid_to_string(&info.ssid);
            let bssid     = mac_u8_to_string(&info.bssid);
            let channel   = Self::freq_to_channel(info.frequency);
            let frequency = Self::get_frequency(channel);

            self.add_info(ssid, bssid, channel, frequency)
        }
    }



    fn ssid_to_string(ssid: &[i8]) -> String {
        let bytes: Vec<u8> = ssid
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as u8)
            .collect();

        String::from_utf8_lossy(&bytes).to_string()
    }



    fn freq_to_channel(freq: u32) -> u8 {
        match freq {
            2412..=2472 => ((freq - 2407) / 5) as u8,
            2484        => 14,
            5000..=5900 => ((freq - 5000) / 5) as u8,
            _           => 0,
        }
    }



    fn get_frequency(channel: u8) -> String {
        if channel <= 14 {"2.4".to_string()} else {"5".to_string()}
    }
    


    fn sniff_beacons(&mut self) {
        println!("Sniffing beacons on monitor mode");

        let beacons = self.start_sniffing();
        self.process_beacons(beacons);
    }



    fn start_sniffing(&mut self) -> Vec<Vec<u8>> {
        let mut sniffer = PacketSniffer::new(
            self.args.iface.clone(),
            "type mgt and subtype beacon".to_string()
        );
        
        sniffer.start();
        self.sniff_2g_channels();
        self.sniff_5g_channels();
        sniffer.stop();

        sniffer.get_packets()
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
            println!("\nUneable to set channel {}", channel);
            return;
        }

        inline_display(&format!("Sniffing channel {} ({}G)", channel, frequency));
        thread::sleep(Duration::from_millis(300));
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



    fn add_info(
        &mut self, 
        ssid      : String, 
        bssid     : String, 
        channel   : u8, 
        frequency : String
    ) {
        self.wifis
            .entry(ssid)
            .and_modify(|existing_info| {
                existing_info.bssids.insert(bssid.clone());
            })
            .or_insert_with(|| {
                Info::new(bssid, channel, frequency.to_string())
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
        let bssids: Vec<&String> = info.bssids.iter().collect();
        
        println!(
            "{:<width$}  {}  {:<7}  {}G",
            name, 
            bssids.first().unwrap_or(&&"N/A".to_string()), 
            info.channel,
            info.frequency,
            width = max_len
        );
        
        for bssid in bssids.iter().skip(1) {
            println!("{:<width$}  {}", "", bssid, width = max_len);
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
    bssids    : HashSet<String>,
    channel   : u8,
    frequency : String
}


impl Info {
    fn new(
        bssid     : String, 
        channel   : u8, 
        frequency : String
    ) -> Self {
        let mut bssids = HashSet::new();
        bssids.insert(bssid);

        Self { bssids, channel, frequency }
    }
}