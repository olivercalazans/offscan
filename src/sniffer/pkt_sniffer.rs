use std::{thread, time::Duration, sync::{Arc, Mutex}, sync::atomic::{AtomicBool, Ordering}};
use pcap::{Device, Capture};



pub struct PacketSniffer {
    filter   : String,
    handle   : Option<thread::JoinHandle<()>>,
    iface    : String,
    raw_pkts : Arc<Mutex<Vec<Vec<u8>>>>,
    running  : Arc<AtomicBool>,
}



impl PacketSniffer {

    pub fn new(iface: String, filter: String) -> Self {
        Self {
            filter,
            iface,
            handle   : None,
            raw_pkts : Arc::new(Mutex::new(Vec::new())),
            running  : Arc::new(AtomicBool::new(false)),
        }
    }



    pub fn start(&mut self) {
        self.running.store(true, Ordering::Relaxed);
        let running = Arc::clone(&self.running);
        let packets = Arc::clone(&self.raw_pkts);
        let cap     = self.create_sniffer();

        self.handle = Some(thread::spawn(move || {
            Self::capture_loop(cap, running, packets)
        }));
    }



    fn create_sniffer(&self) -> Capture<pcap::Active> {
        let dev     = self.get_default_iface();
        let mut cap = self.open_capture(dev.clone());
        cap.filter(&self.filter, true).unwrap();
        
        let cap = cap.setnonblock().unwrap();
        cap
    }



    fn get_default_iface(&self) -> Device {
        Device::list()
            .unwrap()
            .into_iter()
            .find(|d| d.name == self.iface)
            .unwrap_or_else(|| panic!("Interface '{}' not found", self.iface))
    }



    fn open_capture(&self, dev: Device) -> Capture<pcap::Active> {
        Capture::from_device(dev).unwrap()
            .promisc(false)
            .immediate_mode(true)
            .open()
            .unwrap()
    }



    fn capture_loop(mut cap: Capture<pcap::Active>, running: Arc<AtomicBool>, packets: Arc<Mutex<Vec<Vec<u8>>>>) {
        while running.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(pkt) => {
                    if let Ok(mut v) = packets.lock() {
                        v.push(pkt.data.to_vec());
                    }
                }
                Err(_) => std::thread::sleep(Duration::from_micros(500)),
            }
        }
        Self::display_pcap_stats(&mut cap);
    }



    fn display_pcap_stats(cap: &mut Capture<pcap::Active>) {
        match cap.stats() {
            Ok(stats) => {
                println!(
                    "Packets received = {}, dropped = {}, if_dropped = {}",
                    stats.received, stats.dropped, stats.if_dropped
                );
            }
            Err(err) => {
                eprintln!("[ ERROR ] failed to get stats: {}", err);
            }
        }
    }



    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);

        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }



    pub fn get_packets(&self) -> Vec<Vec<u8>> {
        self.raw_pkts.lock().unwrap().clone()
    }

}
