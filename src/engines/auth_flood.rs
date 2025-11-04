use std::{thread, time::Duration};
use crate::iface::{IfaceInfo, InterfaceManager};
use crate::sniffer::PacketSniffer;



pub struct AuthenticationFlooder;



impl AuthenticationFlooder {

    pub fn execute() {
        let iface = "wlp2s0".to_string();
        InterfaceManager::enable_monitor_mode(&iface);
        
        let mut sniffer = PacketSniffer::new(iface.clone(), Self::get_bpf_filter());
        
        sniffer.start();
        thread::sleep(Duration::from_secs(3));
        sniffer.stop();
    }


    


    fn get_bpf_filter() -> String {
        "type mgt and subtype beacon".into()
    }

}