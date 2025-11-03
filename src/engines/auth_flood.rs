use std::{thread, time::Duration};
use crate::iface::{IfaceInfo, InterfaceManager};
use crate::pkt_kit::PacketSniffer;



pub struct AuthenticationFlooder;



impl AuthenticationFlooder {

    pub fn execute() {
        let iface = "wlp2s0".to_string();
        InterfaceManager::enable_monitor_mode(&iface);
        println!("iface down");
    }


    


    fn get_bpf_filter() -> String {
        "ether[0] & 1 = 1 and ether[1] = 0x50".into()
    }

}