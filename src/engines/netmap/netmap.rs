use std::{thread, time::Duration, collections::BTreeMap, mem, net::Ipv4Addr};
use crate::engines::NetMapArgs;
use crate::generators::{Ipv4Iter, DelayIter, RandomValues};
use crate::iface::IfaceInfo;
use crate::pkt_builder::PacketBuilder;
use crate::sniffer::PacketSniffer;
use crate::sockets::Layer3RawSocket;
use crate::dissectors::PacketDissector;
use crate::utils::{abort, get_host_name, get_first_and_last_ip, parse_ip};




pub struct NetworkMapper {
    args:        NetMapArgs,
    active_ips:  BTreeMap<Ipv4Addr, Vec<String>>,
    my_ip:       Ipv4Addr,
    raw_pkts:    Vec<Vec<u8>>,
    start_bound: Option<u32>,
    end_bound:   Option<u32>,
}


struct Iterators {
    ips:    Ipv4Iter,
    delays: DelayIter,
}

struct PacketTools {
    builder: PacketBuilder,
    socket:  Layer3RawSocket,
}



impl NetworkMapper {

    pub fn new(args:NetMapArgs) -> Self {
        Self {
            active_ips:  BTreeMap::new(),
            my_ip:       IfaceInfo::iface_ip(&args.iface).unwrap_or_else(|e| abort(e)),
            raw_pkts:    Vec::new(),
            start_bound: None,
            end_bound:   None,
            args,
        }
    }



    pub fn execute(&mut self) {
        self.validate_protocol_flags();
        self.send_and_receive();
        self.parse_range_to_bounds();
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
        
        self.create_proto_thread();
        
        thread::sleep(Duration::from_secs(3));
        sniffer.stop();
        
        self.raw_pkts = sniffer.get_packets()
    }



    fn get_bpf_filter(&self) -> String {
        format!("ip and dst host {}", self.my_ip)
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
    }



    fn create_thread(&self, probe_type: String) -> thread::JoinHandle<()> {
        println!("Sending {} probes", probe_type.to_uppercase());

        let iters = self.setup_iterators();
        let tools = self.setup_tools();
        let my_ip = self.my_ip.clone();

        thread::spawn(move || {
            Self::send_probes(&probe_type, my_ip, iters, tools);
        })
    }



    fn setup_iterators(&self) -> Iterators {
        let cidr   = self.get_cidr();
        let ips    = Ipv4Iter::new(&cidr, self.args.range.as_deref());
        let len    = ips.total() as usize;
        let delays = DelayIter::new(&self.args.delay, len);
        
        Iterators {ips, delays}
    }



    fn get_cidr(&self) -> String {
        IfaceInfo::iface_cidr(&self.args.iface).unwrap_or_else(|e| abort(e))
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



    fn parse_range_to_bounds(&mut self) {
        let (start, end) = match &self.args.range {
            None => {
                let (first, last) = get_first_and_last_ip(&self.args.iface);
                (Some(first), Some(last))
            }
            Some(s) => {
                if s.contains('*') {
                    self.get_specific_range_with_cidr(s)
                } else {
                    let ip: Ipv4Addr = s.parse().unwrap_or_else(|e| {
                        abort(&format!("Invalid IP address '{}': {}", s, e));
                    });
                    let ip_u32 = u32::from_be_bytes(ip.octets());
                    (Some(ip_u32), Some(ip_u32))
                }
            }
        };

        self.start_bound = start;
        self.end_bound   = end;
    }




    fn get_specific_range_with_cidr(&self, range_str: &str) -> (Option<u32>, Option<u32>) {
        let parts: Vec<&str> = range_str.split('*').collect();
        
        if parts.len() != 2 {
            abort(&format!("Invalid range format: {}", range_str));
        }
    
        let start_str = parts[0].trim();
        let end_str   = parts[1].trim();
    
        let (cidr_first, cidr_last) = get_first_and_last_ip(&self.args.iface);
    
        let start = if start_str.is_empty() {
            Some(cidr_first)
        } else {
            let ip = parse_ip(start_str);
            Some(u32::from_be_bytes(ip.octets()))
        };
    
        let end = if end_str.is_empty() {
            Some(cidr_last)
        } else {
            let ip = parse_ip(end_str);
            Some(u32::from_be_bytes(ip.octets()))
        };
    
        if let (Some(start_val), Some(end_val)) = (start, end) {
            if start_val > end_val {
                abort(&format!(
                    "Start IP ({}) cannot be greater than end IP ({})",
                    Ipv4Addr::from(start_val.to_be_bytes()),
                    Ipv4Addr::from(end_val.to_be_bytes())
                ));
            }
        }
    
        (start, end)
    }



    fn process_raw_packets(&mut self) {
        let raw_pkts      = mem::take(&mut self.raw_pkts);
        let mut dissector = PacketDissector::new(); 

        for packet in raw_pkts.into_iter() {
            dissector.update_pkt(packet);

            let src_ip = match dissector.get_src_ip() {
                Some(ip) => ip,
                None     => continue,
            };

            if self.active_ips.contains_key(&src_ip) || !self.ip_in_range(src_ip) { 
                continue
            }

            let mac_addr    = dissector.get_src_mac().unwrap_or_else(|| "Unknown".to_string());
            let device_name = get_host_name(&src_ip.to_string());

            self.active_ips.insert(src_ip, vec![mac_addr, device_name]);
        }
    }



    #[inline]
    fn ip_in_range(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from_be_bytes(ip.octets());
        
        let lower_ok = match self.start_bound {
            Some(start) => ip_u32 >= start,
            None        => true,
        };

        let upper_ok = match self.end_bound {
            Some(end) => ip_u32 <= end,
            None      => true,
        };

        lower_ok && upper_ok
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



impl crate::EngineTrait for NetworkMapper {
    type Args = NetMapArgs;
    
    fn new(args: Self::Args) -> Self {
        NetworkMapper::new(args)
    }
    
    fn execute(&mut self) {
        self.execute();
    }
}