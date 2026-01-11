use std::{thread, time::Duration, net::Ipv4Addr, collections::BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::iter::Zip;
use crate::engines::PortScanArgs;
use crate::generators::{DelayIter, PortIter, RandomValues};
use crate::iface::IfaceInfo;
use crate::builders::{Packets, UdpPayloads};
use crate::sniffer::Sniffer;
use crate::sockets::Layer3Socket;
use crate::dissectors::PacketDissector;
use crate::utils::{inline_display, get_host_name, abort, CtrlCHandler};



pub struct PortScanner {
    args       : PortScanArgs,
    iface      : String,
    my_ip      : Ipv4Addr,
    open_ports : Arc<Mutex<BTreeSet<u16>>>,
    handle     : Option<thread::JoinHandle<()>>,
    running    : Arc<AtomicBool>
}



impl PortScanner {

    pub fn new(args: PortScanArgs) -> Self {
        let iface = IfaceInfo::iface_from_ip(args.target_ip.clone());

        Self {
            my_ip      : IfaceInfo::ip(&iface).unwrap_or_else(|e| abort(e)),
            open_ports : Arc::new(Mutex::new(BTreeSet::new())),
            running    : Arc::new(AtomicBool::new(false)),
            handle     : None,
            args,
            iface,
        }
    }



    pub fn execute(&mut self) {
        self.display_info();
        self.start_pkt_processor();
        self.send_probes();
        self.stop_pkt_processor();
        self.display_result();
    }



    fn display_info(&self) {
        println!("Target..: {}", self.args.target_ip);
        println!("Iface...: {}", self.iface);
        println!("Proto...: {}", if self.args.udp {"UDP"} else {"TCP"});
    }



    fn start_pkt_processor(&mut self) {
        let sniffer    = Sniffer::new(self.iface.clone(), self.get_bpf_filter(), false);
        let dissector  = PacketDissector::new();
        let open_ports = Arc::clone(&self.open_ports);
        let is_udp     = self.args.udp.clone();

        self.running.store(true, Ordering::Relaxed);
        let running = Arc::clone(&self.running);

        self.handle = Some(thread::spawn(move || {
            Self::sniff_and_dissect(sniffer, dissector, open_ports, running, is_udp)
        }));
    }



    fn get_bpf_filter(&self) -> String {
        if self.args.udp {
            return format!(
                "udp and dst host {} and src host {}",
                self.my_ip, self.args.target_ip
            );
        }

        format!(
            "tcp[13] & 0x12 == 0x12 and dst host {} and src host {}",
            self.my_ip, self.args.target_ip
        )
    }



    fn sniff_and_dissect(
        mut sniffer    : Sniffer,
        mut dissector  : PacketDissector,
        mut open_ports : Arc<Mutex<BTreeSet<u16>>>,
        running        : Arc<AtomicBool>,
        is_udp         : bool,
    ) {
        let recx = sniffer.start();

        while running.load(Ordering::Relaxed) {
            match recx.try_recv() {
                Ok(pkt) => {
                    Self::dissect_and_update(
                        &mut dissector, &mut open_ports, is_udp, pkt
                    );
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    abort("Unknown error in sniffer or channel");
                }
            }
        }

        sniffer.stop();
    }



    #[inline]
    fn dissect_and_update(
        dissector  : &mut PacketDissector,
        open_ports : &mut Arc<Mutex<BTreeSet<u16>>>,
        is_udp     : bool,
        pkt        : Vec<u8>,
    ) {
        dissector.update_pkt(pkt);

        let port = if is_udp {
            dissector.get_udp_src_port()
        } else {
            dissector.get_tcp_src_port()
        };
    
        if port.is_some() {
            open_ports.lock().unwrap().insert(port.unwrap());
        }
    }



    fn stop_pkt_processor(&mut self) {
        self.running.store(false, Ordering::Relaxed);

        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }



    fn send_probes(&mut self) {
        match self.args.udp {
            true  => { self.send_udp_probes(); }
            false => { self.send_tcp_probes(); }
        }
        println!("");
    }



    fn send_tcp_probes(&mut self) {
        let mut tools = self.setup_tools();
        let mut iters = self.setup_tcp_iterators();
        let mut rand  = RandomValues::new(None, None);
        let running = Arc::new(AtomicBool::new(true));
        CtrlCHandler::setup(running.clone());

        while running.load(Ordering::SeqCst) {
            if let Some((port, delay)) = iters.next() {
                let src_port = rand.random_port();
                
                let pkt = tools.builder.tcp_ip(
                    self.my_ip, src_port, 
                    self.args.target_ip, port
                );

                tools.socket.send_to(pkt, self.args.target_ip);
                Self::display_and_sleep(port, delay);
            } else {
                break;
            }
        }
    }



    fn setup_tcp_iterators(&self) -> Zip<PortIter, DelayIter> {
        let ports  = PortIter::new(self.args.ports.clone(), self.args.random.clone());
        let delays = DelayIter::new(&self.args.delay, ports.len());
        
        ports.zip(delays)
    }



    fn send_udp_probes(&mut self) {
        let mut tools = self.setup_tools();
        let mut iters = self.setup_udp_iterators();
        let mut rand  = RandomValues::new(None, None);
        let running   = Arc::new(AtomicBool::new(true));
        CtrlCHandler::setup(running.clone());

        while running.load(Ordering::SeqCst) {
            if let Some(((port, payload), delay)) = iters.next() {
                let src_port = rand.random_port();
                
                let pkt = tools.builder.udp_ip(
                    self.my_ip, src_port, 
                    self.args.target_ip, port, 
                    &payload
                );
                
                tools.socket.send_to(pkt, self.args.target_ip);
                Self::display_and_sleep(port, delay);
            } else {
                break;
            }
        }
    }



    fn setup_udp_iterators(&self) -> impl Iterator<Item = ((u16, Vec<u8>), f32)> + '_ {
        let payloads = UdpPayloads::new(self.my_ip.clone());
        let delays   = DelayIter::new(&self.args.delay, payloads.len());

        let collected: Vec<_> = payloads.iter()
            .map(|(port, payload)| (port, payload.clone()))
            .collect();

        collected.into_iter().zip(delays)
    }



    fn setup_tools(&self) -> PacketTools {
        PacketTools {
            builder : Packets::new(),
            socket  : Layer3Socket::new(&self.iface),
        }
    }


    
    #[inline]
    fn display_and_sleep(port: u16, delay: f32) {
        let msg = format!("Packet sent to port {:<5} - delay: {:.2}", port, delay);
        inline_display(&msg);
        thread::sleep(Duration::from_secs_f32(delay));
    }



    fn display_result(&self) {
        let device_name = get_host_name(&self.args.target_ip.to_string());
        let ports       = self.format_ports();

        println!("\nOpen ports from {} ({})", device_name, self.args.target_ip);
        println!("{}", ports);
    }



    fn format_ports(&self) -> String {
        self.open_ports.lock()
            .unwrap()
            .iter()
            .map(|port| port.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    }

}



impl crate::EngineTrait for PortScanner {
    type Args = PortScanArgs;
    
    fn new(args: Self::Args) -> Self {
        PortScanner::new(args)
    }
    
    fn execute(&mut self) {
        self.execute();
    }
}



struct PacketTools {
    builder : Packets,
    socket  : Layer3Socket,
}