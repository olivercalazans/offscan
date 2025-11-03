use std::{thread, time::Duration};
use crate::iface::{IfaceInfo, WifiModeController};
use crate::pkt_kit::PacketSniffer;



pub struct AuthenticationFlooder;



impl AuthenticationFlooder {

    pub fn execute() {
        let mut sniffer = PacketSniffer::new(IfaceInfo::default_iface_name(), Self::get_bpf_filter(), false);
        sniffer.start();
        thread::sleep(Duration::from_secs(3));
        sniffer.stop();
    }


    fn get_bpf_filter() -> String {
        "type mgt and subtype beacon".into()
    }

}