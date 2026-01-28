use std::{thread, time::Duration, net::Ipv4Addr, collections::BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::iter::Zip;
use crate::engines::PortScanArgs;
use crate::generators::{DelayIter, PortIter, RandomValues};
use crate::iface::{Iface, SysInfo};
use crate::builders::{Packets, UdpPayloads};
use crate::sniffer::Sniffer;
use crate::sockets::Layer3Socket;
use crate::dissectors::PacketDissector;
use crate::utils::{get_host_name, abort};



pub struct PortScanner {
    iface      : Iface,
    my_ip      : Ipv4Addr,
    target_ip  : Ipv4Addr,
    ports      : Option<String>,
    random     : bool,
    delay      : String,
    udp        : bool,
    open_ports : Arc<Mutex<BTreeSet<u16>>>,
    handle     : Option<thread::JoinHandle<()>>,
    running    : Arc<AtomicBool>
}



impl PortScanner {

    pub fn new(args: PortScanArgs) -> Self {
        let iface = SysInfo::iface_from_ip(args.target_ip);

        Self {
            my_ip      : iface.ip().unwrap_or_else(|e| abort(e)),
            open_ports : Arc::new(Mutex::new(BTreeSet::new())),
            running    : Arc::new(AtomicBool::new(false)),
            handle     : None,
            target_ip  : args.target_ip,
            ports      : args.ports,
            random     : args.random,
            delay      : args.delay,
            udp        : args.udp,
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
        println!("Iface...: {}", self.iface.name());
        println!("Target..: {}", self.target_ip);
        println!("Proto...: {}", if self.udp {"UDP"} else {"TCP"});
    }



    fn start_pkt_processor(&mut self) {
        let iface_name = self.iface.name().to_string();
        let sniffer    = Sniffer::new(iface_name, self.get_bpf_filter(), false);
        let dissector  = PacketDissector::new();
        let open_ports = Arc::clone(&self.open_ports);
        let is_udp     = self.udp.clone();

        self.running.store(true, Ordering::Relaxed);
        let running = Arc::clone(&self.running);

        self.handle = Some(thread::spawn(move || {
            Self::sniff_and_dissect(sniffer, dissector, open_ports, running, is_udp)
        }));
    }



    fn get_bpf_filter(&self) -> String {
        if self.udp {
            return format!(
                "udp and dst host {} and src host {}",
                self.my_ip, self.target_ip
            );
        }

        format!(
            "tcp[13] & 0x12 == 0x12 and dst host {} and src host {}",
            self.my_ip, self.target_ip
        )
    }



    fn sniff_and_dissect(
        mut sniffer   : Sniffer,
        mut dissector : PacketDissector,
        open_ports    : Arc<Mutex<BTreeSet<u16>>>,
        running       : Arc<AtomicBool>,
        is_udp        : bool,
    ) {
        let recx = sniffer.start();
        let mut temp_buf: BTreeSet<u16> = BTreeSet::new();

        while running.load(Ordering::Relaxed) {
            match recx.try_recv() {
                Ok(pkt) => {
                    Self::dissect_and_update(
                        &mut dissector, &mut temp_buf, is_udp, pkt
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
        let mut guard = open_ports.lock().unwrap();
        *guard = temp_buf;
    }



    #[inline]
    fn dissect_and_update(
        dissector : &mut PacketDissector,
        temp_buf  : &mut BTreeSet<u16>,
        is_udp    : bool,
        pkt       : Vec<u8>,
    ) {
        dissector.update_pkt(pkt);

        let port = if is_udp {
            dissector.get_udp_src_port()
        } else {
            dissector.get_tcp_src_port()
        };
    
        if port.is_some() {
            temp_buf.insert(port.unwrap());
        }
    }



    fn stop_pkt_processor(&mut self) {
        self.running.store(false, Ordering::Relaxed);

        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }



    fn send_probes(&mut self) {
        match self.udp {
            true  => { self.send_udp_probes(); }
            false => { self.send_tcp_probes(); }
        }
        println!("");
        std::thread::sleep(Duration::from_secs(3))
    }



    fn send_tcp_probes(&mut self) {
        let iters     = self.setup_tcp_iterators();
        let mut tools = self.setup_tools();
        let mut rand  = RandomValues::new(None, None);

        for (port, delay) in iters{
            let src_port = rand.random_port();
                
            let pkt = tools.builder.tcp_ip(
                self.my_ip, src_port, 
                self.target_ip, port
            );

            tools.socket.send_to(pkt, self.target_ip);
            thread::sleep(Duration::from_secs_f32(delay));
        }
    }



    fn setup_tcp_iterators(&self) -> Zip<PortIter, DelayIter> {
        let ports  = PortIter::new(self.ports.clone(), self.random.clone());
        let delays = DelayIter::new(&self.delay, ports.len());
        
        ports.zip(delays)
    }



    fn send_udp_probes(&mut self) {
        let iters     = self.setup_udp_iterators();
        let mut tools = self.setup_tools();
        let mut rand  = RandomValues::new(None, None);

        for ((port, payload), delay) in iters {
            let src_port = rand.random_port();
                
            let pkt = tools.builder.udp_ip(
                self.my_ip, src_port, 
                self.target_ip, port, 
                &payload
            );
                
            tools.socket.send_to(pkt, self.target_ip);
            thread::sleep(Duration::from_secs_f32(delay));
        }
    }



    fn setup_udp_iterators(&self) -> impl Iterator<Item = ((u16, Vec<u8>), f32)> + '_ {
        let payloads = UdpPayloads::new(self.my_ip.clone());
        let delays   = DelayIter::new(&self.delay, payloads.len());

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



    fn display_result(&self) {
        let device_name = get_host_name(&self.target_ip.to_string());
        let ports       = self.format_ports();

        println!("\nOpen ports from {} ({})", device_name, self.target_ip);
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