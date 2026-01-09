use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use crate::engines::FakeApsArgs;
use crate::iface::IfaceManager;
use crate::builders::Frames;
use crate::sockets::Layer2Socket;
use crate::generators::RandomValues;
use crate::utils::{ CtrlCHandler, inline_display, abort };



pub struct FakeAps {
    args    : FakeApsArgs,
    bc_sent : usize,
    builder : Frames,
    socket  : Layer2Socket,
}


impl FakeAps {

    pub fn new(args: FakeApsArgs) -> Self {
        Self { 
            bc_sent : 0,
            builder : Frames::new(),
            socket  : Layer2Socket::new(&args.iface),
            args, 
        }
    }



    pub fn execute(&mut self) {
        self.set_channel();
        self.send_endlessly();
    }



    fn set_channel(&self) {
        if !IfaceManager::set_channel(&self.args.iface, self.args.channel) {
            abort(
                format!(
                    "Uneable to set channel {} on interface {}", 
                    self.args.iface, 
                    self.args.channel
                )
            )
        }
    }



    fn send_endlessly(&mut self) {
        let mut rand = RandomValues::new(None, None); 
        let running  = Arc::new(AtomicBool::new(true));
        CtrlCHandler::setup(running.clone());


        while running.load(Ordering::SeqCst) {
            let bssid = rand.random_mac();
            let seq   = rand.random_seq();
            let ssid  = rand.random_case_inversion(&self.args.ssid);
            
            self.send_beacon(bssid, &ssid, seq);
            self.send_beacon(bssid, &ssid, seq + 1);
            self.send_beacon(bssid, &ssid, seq + 2);
        }
        
        println!("\nFlood interrupted"); 
    }



    #[inline]
    fn send_beacon(
        &mut self, 
        bssid : [u8; 6], 
        ssid  : &str,
        seq   : u16,
    ) {
        let beacon = self.builder.beacon(bssid, ssid, seq, self.args.channel as u8);
        
        self.socket.send(beacon);
        self.bc_sent += 1;

        inline_display(&format!("Beacons sent: {}", &self.bc_sent));
    }

}




impl crate::EngineTrait for FakeAps {
    type Args = FakeApsArgs;
    
    fn new(args: Self::Args) -> Self {
        FakeAps::new(args)
    }
    
    fn execute(&mut self) {
        self.execute();
    }
}