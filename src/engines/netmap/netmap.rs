use std::{thread, time::Duration, collections::BTreeMap, mem, net::Ipv4Addr};
use crate::engines::NetMapArgs;
use crate::generators::{Ipv4Iter, DelayIter, RandValues};
use crate::iface::IfaceInfo;
use crate::pkt_builder::PacketBuilder;
use crate::sniffer::PacketSniffer;
use crate::sockets::Layer3RawSocket;
use crate::dissectors::PacketDissector;
use crate::utils::{abort, get_host_name};



struct Iterators {
    ips:    Ipv4Iter,
    delays: DelayIter,
}

struct PacketTools {
    builder: PacketBuilder,
    socket:  Layer3RawSocket,
}



pub struct NetworkMapper {
    args:       NetMapArgs,
    active_ips: BTreeMap<Ipv4Addr, Vec<String>>,
    my_ip:      Ipv4Addr,
    raw_pkts:   Vec<Vec<u8>>,
}


impl NetworkMapper {

    pub fn new(args:NetMapArgs) -> Self {
        Self {
            active_ips: BTreeMap::new(),
            my_ip:      IfaceInfo::iface_ip(&args.iface).unwrap_or_else(|e| abort(e)),
            raw_pkts:   Vec::new(),
            args,
        }
    }



    pub fn execute(&mut self) {
        self.validate_protocol_flags();
        self.send_and_receive();
        self.process_raw_packets();
        self.display_result();
    }



    fn validate_protocol_flags(&mut self) {
        if !self.args.icmp && !self.args.tcp && !self.args.udp {
            self.args.icmp = true;
            self.args.tcp  = true;
            self.args.udp  = true;
        }
    }



    fn send_and_receive(&mut self) {    
        let mut sniffer = PacketSniffer::new(self.args.iface.clone(), self.get_bpf_filter());   
        
        sniffer.start();
        
        self.send_icmp_and_tcp_probes();
        
        thread::sleep(Duration::from_secs(3));
        sniffer.stop();
        
        self.raw_pkts = sniffer.get_packets()
    }



    fn get_bpf_filter(&self) -> String {
        format!(
            "(dst host {} and src net {}) and (tcp or icmp or udp)", 
            self.my_ip, self.get_cidr())
    }



    fn get_cidr(&self) -> String {
        IfaceInfo::iface_network_cidr(&self.args.iface).unwrap_or_else(|e| abort(e))
    }



    fn send_icmp_and_tcp_probes(&mut self) {
        let icmp_thread = if self.args.icmp {
            println!("Sending ICMP probes");
            Some(self.create_thread("icmp".to_string()))
        } else {
            None
        };

        let tcp_thread = if self.args.tcp {
            println!("Sending TCP probes");
            Some(self.create_thread("tcp".to_string()))
        } else {
            None
        };


        let udp_thread = if self.args.udp {
            println!("Sending UDP probes");
            Some(self.create_thread("udp".to_string()))
        } else {
            None
        };


        if let Some(thread) = icmp_thread {
            thread.join().expect("ICMP thread failed");
        }

        if let Some(thread) = tcp_thread {
            thread.join().expect("TCP thread failed");
        }

        if let Some(thread) = udp_thread {
            thread.join().expect("UDP thread failed");
        }
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
        let cidr   = self.get_cidr();
        let ips    = Ipv4Iter::new(&cidr, self.args.start_ip.clone(), self.args.end_ip.clone());
        let len    = ips.total() as usize;
        let delays = DelayIter::new(&self.args.delay, len);
        
        Iterators {ips, delays}
    }



    fn setup_tools(&self) -> PacketTools {
        PacketTools {
            builder: PacketBuilder::new(),
            socket:  Layer3RawSocket::new(&self.args.iface),
        }
    }



    fn send_probes(
        probe_type: &str,
        my_ip:      Ipv4Addr,
        mut iters:  Iterators,
        mut tools:  PacketTools
    ) {
        let mut rand = RandValues::new(None, None);

        iters.ips.by_ref()
            .zip(iters.delays.by_ref())
            .for_each(|(dst_ip, delay)| {
                let pkt = match probe_type {
                    "icmp" => tools.builder.icmp_ping(my_ip, dst_ip),
                    "tcp"  => tools.builder.tcp_ip(my_ip, rand.get_random_port(), dst_ip, 80),
                    "udp"  => tools.builder.udp_ip(my_ip, rand.get_random_port(), dst_ip, 53, &[]),
                    &_     => abort(format!("Unknown protocol type: {}", probe_type)),
                };
                tools.socket.send_to(&pkt, dst_ip);
            
                thread::sleep(Duration::from_secs_f32(delay));
            });
        println!("");
    }



    fn process_raw_packets(&mut self) {
        let raw_pkts = mem::take(&mut self.raw_pkts);

        for packet in raw_pkts.into_iter() {
            let str_ip           = PacketDissector::get_src_ip(&packet);
            let src_ip: Ipv4Addr = str_ip.parse().unwrap();

            if self.active_ips.contains_key(&src_ip) { continue }

            let mut info: Vec<String> = Vec::new();

            let mac_addr = PacketDissector::get_src_mac(&packet);
            info.push(mac_addr);

            let device_name = get_host_name(&str_ip);
            info.push(device_name);

            self.active_ips.insert(src_ip, info);
        }
    }



    fn display_result(&mut self) {
        Self::display_header();
        let active_ips = mem::take(&mut self.active_ips);

        for (ip, host) in active_ips {
            println!("{}", format!("{:<15}  {}  {}", ip, host[0], host[1]));
        }
    }



    fn display_header() {
        println!("{}", format!("\n{:<15}  {:<17}  {}", "IP Address", "MAC Address", "Hostname"));
        println!("{}", format!("{}  {}  {}", "-".repeat(15), "-".repeat(17), "-".repeat(8)));
    }

}