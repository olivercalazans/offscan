use std::{thread, time::Duration, collections::BTreeMap, mem, net::Ipv4Addr};
use crate::arg_parser::NetMapArgs;
use crate::generators::{Ipv4Iter, DelayIter, RandValues};
use crate::iface::IfaceInfo;
use crate::pkt_builder::PacketBuilder;
use crate::sniffer::PacketSniffer;
use crate::sockets::Layer3RawSocket;
use crate::dissectors::PacketDissector;
use crate::utils::{abort, inline_display, get_host_name};



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
            my_ip:      IfaceInfo::iface_ip(&args.iface),
            raw_pkts:   Vec::new(),
            args,
        }
    }



    pub fn execute(&mut self) {
        self.send_and_receive();
        self.process_raw_packets();
        self.display_result();
    }



    fn send_and_receive(&mut self) {
        let mut tools = self.setup_tools();
        let mut iters = self.setup_iterators();
        
        tools.sniffer.start();
        
        self.send_icmp_and_tcp_probes(&mut tools, &mut iters);
        
        thread::sleep(Duration::from_secs(3));
        tools.sniffer.stop();
        
        self.raw_pkts = tools.sniffer.get_packets()
    }



    fn setup_tools(&self) -> PacketTools {
        PacketTools {
            sniffer: PacketSniffer::new(self.args.iface.clone(), self.get_bpf_filter()),
            builder: PacketBuilder::new(),
            socket:  Layer3RawSocket::new(&self.args.iface),
        }
    }



    fn get_bpf_filter(&self) -> String {
        format!(
            "(dst host {} and src net {}) and (tcp or (icmp and icmp[0] = 0))",
            self.my_ip, IfaceInfo::iface_network_cidr(&self.args.iface)
        )
    }



    fn setup_iterators(&self) -> Iterators {
        let cidr   = IfaceInfo::iface_network_cidr(&self.args.iface);
        let ips    = Ipv4Iter::new(&cidr, self.args.start_ip.clone(), self.args.end_ip.clone());
        let len    = ips.total() as usize;
        let delays = DelayIter::new(&self.args.delay, len);
        
        Iterators {ips, delays, len}
    }



    fn send_icmp_and_tcp_probes(&mut self, tools: &mut PacketTools, iters: &mut Iterators) {
        println!("Sending ICMP probes");
        self.send_probes("icmp", tools, iters);
        
        iters.ips.reset();
        iters.delays.reset();

        println!("Sending TCP probes");
        self.send_probes("tcp", tools, iters);     
    }



    fn send_probes(
        &mut self,
        probe_type: &str,
        tools:      &mut PacketTools,
        iters:      &mut Iterators
    ) {
        let mut rand = RandValues::new();

        for (i, (dst_ip, delay)) in iters.ips.by_ref().zip(iters.delays.by_ref()).enumerate() {
            let pkt = match probe_type {
                "icmp" => tools.builder.icmp_ping(self.my_ip, dst_ip),
                "tcp"  => tools.builder.tcp_ip(self.my_ip, rand.get_random_port(), dst_ip, 80),
                &_     => abort(format!("Unknown protocol type: {}", probe_type)),
            };
            tools.socket.send_to(&pkt, dst_ip);

            Self::display_progress(i + 1, iters.len , dst_ip.to_string(), delay);
            thread::sleep(Duration::from_secs_f32(delay));
        }
        println!("");
    }



    fn display_progress(i: usize, total: usize, ip: String, delay: f32) {
        let msg = format!("\tPackets sent: {}/{} - {:<15} - delay: {:.2}", i, total, ip, delay);
        inline_display(&msg);
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



struct PacketTools {
    sniffer: PacketSniffer,
    builder: PacketBuilder,
    socket:  Layer3RawSocket,
}



struct Iterators {
    ips:    Ipv4Iter,
    delays: DelayIter,
    len:    usize,
}