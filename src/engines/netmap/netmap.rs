use std::{thread, time::Duration, collections::BTreeMap, net::Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use crate::engines::NetMapArgs;
use crate::generators::{Ipv4Iter, DelayIter, RandomValues};
use crate::iface::IfaceInfo;
use crate::builders::Packets;
use crate::sniffer::Sniffer;
use crate::sockets::Layer3Socket;
use crate::dissectors::PacketDissector;
use crate::utils::{abort, get_host_name};



pub struct NetworkMapper {
    args       : NetMapArgs,
    active_ips : Arc<Mutex<BTreeMap<Ipv4Addr, Info>>>,
    ips        : Ipv4Iter,
    my_ip      : Ipv4Addr,
    handle     : Option<thread::JoinHandle<()>>,
    running    : Arc<AtomicBool>
}


impl NetworkMapper {

    pub fn new(args:NetMapArgs) -> Self {
        let cidr = IfaceInfo::cidr(&args.iface).unwrap_or_else(|e| abort(e));

        Self {
            active_ips : Arc::new(Mutex::new(BTreeMap::new())),
            ips        : Ipv4Iter::new(&cidr, args.range.as_deref()),
            my_ip      : IfaceInfo::ip(&args.iface).unwrap_or_else(|e| abort(e)),
            running    : Arc::new(AtomicBool::new(false)),
            handle     : None,
            args,
        }
    }



    pub fn execute(&mut self) {
        self.validate_protocol_flags();
        self.display_info();
        self.start_pkt_processor();
        self.create_proto_thread(); 
        self.stop_pkt_processor();
        self.get_names();
        self.display_result();
    }



    fn validate_protocol_flags(&mut self) {
        if !self.args.icmp && !self.args.tcp && !self.args.udp {
            self.args.icmp = true;
            self.args.tcp  = true;
            self.args.udp  = true;
        }
    }



    fn display_info(&self) {
        let mut protocols = Vec::new();
        if self.args.icmp { protocols.push("ICMP"); }
        if self.args.tcp { protocols.push("TCP"); }
        if self.args.udp { protocols.push("UDP"); }
        
        let proto = protocols.join(", ");
        let first = Ipv4Addr::from(self.ips.end_u32);
        let last  = Ipv4Addr::from(self.ips.end_u32);
        let len   = self.ips.end_u32 - self.ips.start_u32 + 1;

        println!("Iface..: {}", self.args.iface);
        println!("Range..: {} - {}", first, last);        
        println!("Len IPs: {}", len);
        println!("Proto..: {}", proto);
    }



    fn start_pkt_processor(&mut self) {
        let sniffer    = Sniffer::new(self.args.iface.clone(), self.get_bpf_filter(), false);
        let dissector  = PacketDissector::new();
        let active_ips = Arc::clone(&self.active_ips);
        let start_u32  = self.ips.start_u32.clone();
        let end_u32    = self.ips.end_u32.clone();

        self.running.store(true, Ordering::Relaxed);
        let running = Arc::clone(&self.running);

        self.handle = Some(thread::spawn(move || {
            Self::sniff_and_dissect(
                sniffer, dissector, active_ips, running, start_u32, end_u32
            )
        }));
    }



    fn sniff_and_dissect(
        mut sniffer    : Sniffer,
        mut dissector  : PacketDissector,
        active_ips     : Arc<Mutex<BTreeMap<Ipv4Addr, Info>>>,
        running        : Arc<AtomicBool>,
        start_u32      : u32,
        end_u32        : u32,
    ) {
        let recx = sniffer.start();
        let mut temp_buf: BTreeMap<Ipv4Addr, Info> = BTreeMap::new();

        while running.load(Ordering::Relaxed) {
            match recx.try_recv() {
                Ok(pkt) => {
                    Self::dissect_and_update(
                        &mut dissector, &mut temp_buf, pkt, start_u32, end_u32
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
        let mut guard = active_ips.lock().unwrap();
        *guard = temp_buf;
    }



    #[inline]
    fn dissect_and_update(
        dissector : &mut PacketDissector,
        temp_buf  : &mut BTreeMap<Ipv4Addr, Info>,
        pkt       : Vec<u8>,
        start_u32 : u32,
        end_u32   : u32,
    ) {
        dissector.update_pkt(pkt);

        let src_ip = match dissector.get_src_ip() {
            Some(ip) => ip,
            None     => return,
        };

        if !Self::is_in_range(start_u32, end_u32, src_ip) || temp_buf.contains_key(&src_ip) { 
            return;
        }

        let mac = dissector.get_src_mac().unwrap_or_else(|| "Unknown".to_string());
        temp_buf.insert(src_ip, Info {mac, name: String::new()});
    }



    #[inline]
    fn is_in_range(
        start_u32 : u32, 
        end_u32   : u32, 
        ip        : Ipv4Addr
    ) -> bool {
        let ip_u32 = u32::from_be_bytes(ip.octets());
        
        ip_u32 >= start_u32 || ip_u32 <= end_u32
    }



    fn get_bpf_filter(&self) -> String {
        format!("ip and src net {}", self.cidr_for_bpf_filter())
    }



    fn cidr_for_bpf_filter(&self) -> String {        
        let xor = self.ips.start_u32 ^ self.ips.end_u32;
        
        let leading_zeros = if xor == 0 {
            32
        } else {
            xor.leading_zeros()
        };

        let prefix_len = leading_zeros as u8;

        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };

        let network_addr = self.ips.start_u32 & mask;

        format!("{}/{}", Ipv4Addr::from(network_addr), prefix_len)
    }



    fn stop_pkt_processor(&mut self) {
        self.running.store(false, Ordering::Relaxed);

        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }



    fn create_proto_thread(&mut self) {
        let mut threads = vec![];
        
        let protocols = [
            ("icmp", self.args.icmp),
            ("tcp",  self.args.tcp),
            ("udp",  self.args.udp),
        ];
        
        for (name, flag) in protocols.iter() {
            if *flag {
                threads.push((self.create_thread(name.to_string()), name));
            }
        }

        for (thread, name) in threads {
            thread.join().unwrap_or_else(|_| abort(format!("{} thread failed", name)));
        }

        thread::sleep(Duration::from_secs(3));
    }



    fn create_thread(&self, probe_type: String) -> thread::JoinHandle<()> {
        let iters = self.setup_iterators();
        let tools = self.setup_tools();
        let my_ip = self.my_ip.clone();

        thread::spawn(move || {
            Self::send_probes(&probe_type, my_ip, iters, tools);
        })
    }



    fn setup_iterators(&self) -> Iterators {
        let ips    = self.ips.clone();
        let len    = ips.total() as usize;
        let delays = DelayIter::new(&self.args.delay, len);
        
        Iterators {ips, delays}
    }



    fn setup_tools(&self) -> PacketTools {
        PacketTools {
            builder : Packets::new(),
            socket  : Layer3Socket::new(&self.args.iface),
        }
    }



    fn send_probes(
        probe_type : &str,
        my_ip      : Ipv4Addr,
        mut iters  : Iterators,
        mut tools  : PacketTools
    ) {
        let mut rand = RandomValues::new(None, None);

        iters.ips.by_ref()
            .zip(iters.delays.by_ref())
            .for_each(|(dst_ip, delay)| {
                let pkt = match probe_type {
                    "icmp" => tools.builder.icmp_ping(my_ip, dst_ip),
                    "tcp"  => tools.builder.tcp_ip(my_ip, rand.random_port(), dst_ip, 80),
                    "udp"  => tools.builder.udp_ip(my_ip, rand.random_port(), dst_ip, 53, &[]),
                    &_     => abort(format!("Unknown protocol type: {}", probe_type)),
                };
                tools.socket.send_to(&pkt, dst_ip);
            
                thread::sleep(Duration::from_secs_f32(delay));
            });
    }



    fn get_names(&mut self) {
        let mut guard = self.active_ips.lock().unwrap();
        
        for (ip, info) in guard.iter_mut() {
            let name = get_host_name(&ip.to_string());
            info.name = name;
        }
    }



    fn display_result(&mut self) {
        Self::display_header();

        let guard = self.active_ips.lock().unwrap();
        let map   = &*guard;

        for (ip, info) in map.iter() {
            println!("{}", format!("{:<15}  {}  {}", ip, info.mac, info.name));
        }
    }



    fn display_header() {
        println!("{}", format!("\n{:<15}  {:<17}  {}", "IP Address", "MAC Address", "Hostname"));
        println!("{}", format!("{}  {}  {}", "-".repeat(15), "-".repeat(17), "-".repeat(8)));
    }

}



impl crate::EngineTrait for NetworkMapper {
    type Args = NetMapArgs;
    
    fn new(args: Self::Args) -> Self {
        NetworkMapper::new(args)
    }
    
    fn execute(&mut self) {
        self.execute();
    }
}


struct Info {
    mac  : String,
    name : String,
}


struct Iterators {
    ips    : Ipv4Iter,
    delays : DelayIter,
}

struct PacketTools {
    builder : Packets,
    socket  : Layer3Socket,
}