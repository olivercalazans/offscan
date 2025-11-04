use std::{thread, time::Duration};
use crate::dissectors::BeaconDissector;
use crate::iface::InterfaceManager;
use crate::sniffer::PacketSniffer;



pub struct AuthenticationFlooder;



impl AuthenticationFlooder {

    pub fn execute() {
        let iface = "wlp2s0".to_string();
        InterfaceManager::enable_monitor_mode(&iface);
        
        let mut sniffer = PacketSniffer::new(iface.clone(), Self::get_bpf_filter());
        
        sniffer.start();
        println!("sniffer started");
        thread::sleep(Duration::from_secs(5));
        sniffer.stop();
        println!("sniffer stoped");
        let packets = sniffer.get_packets();

        for p in packets {
            if let Some(info) = BeaconDissector::parse_beacon(&p) {
                println!("{:?}", info);
            }
        }
    }
    


    fn get_bpf_filter() -> String {
        "type mgt and subtype beacon".into()
    }

}
