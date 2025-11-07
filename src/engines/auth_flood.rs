use std::{thread, time::Duration};
use crate::arg_parser::{AuthArgs, parse_mac};
use crate::dissectors::BeaconDissector;
use crate::iface::InterfaceManager;
use crate::sniffer::PacketSniffer;
use crate::utils::abort;



pub struct AuthenticationFlooder {
    args:  AuthArgs,
    iface: String,
}


impl AuthenticationFlooder {

    pub fn new(args: AuthArgs) -> Self {
        Self {
            args,
            iface: "wlp2s0".to_string(),
        }
    }



    pub fn execute() {
        InterfaceManager::enable_monitor_mode(&self.iface);
        
        if !self.args.bssid {
            let bssid = self.resolve_bssid();
        }
    }



    fn resolve_bssid(&mut self) -> [u8; 6] {
        let beacons = self.get_beacons();
        self.process_beacons(beacons)
    }



    fn get_beacons(&mut self) -> Vec<Vec<u8>> {
        InterfaceManager::enable_monitor_mode(&iface);
        
        let mut sniffer = PacketSniffer::new(
            self.iface.clone(), "type mgt and subtype beacon".to_string()
        );
        
        sniffer.start();
        thread::sleep(Duration::from_secs(2));
        sniffer.stop();

        sniffer.get_packets()
    }



    fn process_beacons(&self, beacons: Vec<Vec<u8>>) -> [u8; 6] {
        for b in beacons {
            let into = BeaconDissector::parse_beacon(b);
            if info[0] == self.args.ssid {
                return parse_mac(info[1]);
            }
        }
        
        InterfaceManager::disable_monitor_mode(&iface);
        abort("It was not possible to resolve BSSID. Try again or set a BSSID")
    }

}
