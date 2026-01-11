use std::{thread, time::Duration, collections::BTreeMap, mem};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use crate::engines::wifi_map::WifiData;
use crate::dissectors::BeaconDissector;
use crate::iface::IfaceManager;
use crate::sniffer::Sniffer;
use crate::utils::{inline_display, abort};



pub(super) struct MonitorSniff<'a> {
    iface     : String,
    wifis_buf : &'a mut BTreeMap<String, WifiData>,
    buffer    : Arc<Mutex<BTreeMap<String, WifiData>>>,
    handle    : Option<thread::JoinHandle<()>>,
    running   : Arc<AtomicBool>
}


impl<'a> MonitorSniff<'a> {

    pub fn new(
        iface     : String, 
        wifis_buf : &'a mut BTreeMap<String, WifiData>
    ) -> Self {
        Self { 
            iface, 
            wifis_buf,
            buffer  : Arc::new(Mutex::new(BTreeMap::new())),
            running : Arc::new(AtomicBool::new(false)),
            handle  : None,
        }
    }



    pub fn execute_monitor_sniff(&mut self) {
        self.start_bc_processor();
        self.sniff_2g_channels();
        self.sniff_5g_channels();
        self.stop_bc_processor();
        self.send_data();
    }



    fn start_bc_processor(&mut self) {
        let sniffer = Sniffer::new(self.iface.clone(), Self::get_bpf_filter(), false);
        let buffer  = Arc::clone(&self.buffer);

        self.running.store(true, Ordering::Relaxed);
        let running = Arc::clone(&self.running);

        self.handle = Some(thread::spawn(move || {
            Self::sniff_and_dissect(sniffer, buffer, running)
        }));
    }


    fn get_bpf_filter() -> String {
        "type mgt and subtype beacon".to_string()
    }


    fn sniff_and_dissect(
        mut sniffer : Sniffer,
        buffer      : Arc<Mutex<BTreeMap<String, WifiData>>>,
        running     : Arc<AtomicBool>,
    ) {
        let mut temp_buf: BTreeMap<String, WifiData> = BTreeMap::new();
        let recx = sniffer.start();

        while running.load(Ordering::Relaxed) {
            match recx.try_recv() {
                Ok(beacon) => {
                    Self::dissect_and_update(&mut temp_buf, beacon);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    abort("Unknown error in sniffer or chnl");
                }
            }
        }

        sniffer.stop();
        let mut guard = buffer.lock().unwrap();
        *guard = temp_buf;
    }



    #[inline]
    fn dissect_and_update(
        temp_buf : &mut BTreeMap<String, WifiData>,
        beacon   : Vec<u8>,
    ) {
        if let Some(info) = BeaconDissector::parse_beacon(&beacon) {
            let ssid     = info[0].clone();
            let bssid    = info[1].clone();
            let chnl: u8 = info[2].parse().unwrap_or_else(|_| 0);
            let freq     = Self::get_frequency(chnl);
            let sec      = info[3].clone();
                
            Self::add_info(temp_buf, ssid, bssid, chnl, freq, sec);
        }
    }



    #[inline]
    fn get_frequency(chnl: u8) -> String {
        if chnl <= 14 {"2.4".to_string()} else {"5".to_string()}
    }



    #[inline]
    fn add_info(
        temp_buf : &mut BTreeMap<String, WifiData>,
        ssid     : String, 
        bssid    : String, 
        chnl     : u8, 
        freq     : String,
        sec      : String,
    ) {
        temp_buf
            .entry(ssid)
            .and_modify(|existing_info| {
                existing_info.bssids.insert(bssid.clone());
            })
            .or_insert_with(|| {
                WifiData::new(bssid, chnl, freq.to_string(), sec)
            });
    }



    fn stop_bc_processor(&mut self) {
        self.running.store(false, Ordering::Relaxed);

        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
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
    fn sniff_channels(&self, channels: Vec<i32>, freq: &str) {
        let mut err: Vec<i32> = Vec::new();

        for chnl in channels {
            let done = IfaceManager::set_channel(&self.iface, chnl);

            if !done {
                err.push(chnl);
                continue;
            }

            inline_display(&format!("Sniffing chnl {} ({}G)", chnl, freq));
            thread::sleep(Duration::from_millis(300));
        }

        if err.len() > 0 {
            println!("[!] Uneable to sniff these channels ({}G):\n{:?}", freq, err);
        }
    }



    fn send_data(&mut self) {
        let mut guard = self.buffer.lock().unwrap();
        *self.wifis_buf = mem::take(&mut *guard);
    }

}