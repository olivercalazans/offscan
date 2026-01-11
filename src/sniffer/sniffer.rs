use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc::Receiver};
use std::thread;
use std::time::Duration;
use pcap::{Device, Capture};
use crate::utils::abort;



pub(crate) struct Sniffer {
    filter  : String,
    promisc : bool,
    handle  : Option<thread::JoinHandle<()>>,
    iface   : String,
    running : Arc<AtomicBool>,
}



impl Sniffer {
    
    pub fn new(
        iface   : String, 
        filter  : String, 
        promisc : bool
    ) -> Self 
    {
        Self {
            filter,
            iface,
            promisc,
            handle  : None,
            running : Arc::new(AtomicBool::new(false)),
        }
    }



    pub fn start(&mut self) -> Receiver<Vec<u8>> {
        let (tx, rx) = std::sync::mpsc::channel();
        
        self.running.store(true, Ordering::Relaxed);
        let running = Arc::clone(&self.running);
        let cap     = self.create_sniffer();

        self.handle = Some(thread::spawn(move || {
            Self::capture_loop(cap, running, tx)
        }));

        rx
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
            .unwrap_or_else(|| abort(format!("Interface '{}' not found", self.iface)))
    }



    fn open_capture(&self, dev: Device) -> Capture<pcap::Active> {
        Capture::from_device(dev).unwrap()
            .promisc(self.promisc)
            .immediate_mode(true)
            .open()
            .unwrap()
    }



    fn capture_loop(
        mut cap : Capture<pcap::Active>,
        running : Arc<AtomicBool>,
        sender  : std::sync::mpsc::Sender<Vec<u8>>,
    ) {
        while running.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(pkt) => {
                    if sender.send(pkt.data.to_vec()).is_err() {
                        break;
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
                    "\n[$] Packets received = {}, dropped = {}, if_dropped = {}",
                    stats.received, stats.dropped, stats.if_dropped
                );
            }
            Err(err) => {
                eprintln!("\n[!] failed to get stats: {}", err);
            }
        }
    }



    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);

        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }

}