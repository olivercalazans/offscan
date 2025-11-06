use std::{thread, time::Duration, mem, net::Ipv4Addr};
use crate::arg_parser::PortScanArgs;
use crate::generators::{DelayIter, PortIter, RandValues};
use crate::iface::IfaceInfo;
use crate::pkt_builder::{PacketBuilder, UdpPayloads};
use crate::sniffer::PacketSniffer;
use crate::sockets::Layer3RawSocket;
use crate::dissectors::PacketDissector;
use crate::utils::{inline_display, get_host_name};



struct PacketTools {
    sniffer: PacketSniffer,
    builder: PacketBuilder,
    socket:  Layer3RawSocket,
}



struct UdpIterators {
    ports:  UdpPayloads,
    delays: DelayIter,
    ip:     String,
}



struct TcpIterators {
    ports:  PortIter,
    delays: DelayIter,
    ip:     String,
}



pub struct PortScanner {
    args:        PortScanArgs,
    iface:       String,
    my_ip:       Ipv4Addr,
    rand:        RandValues,
    raw_packets: Vec<Vec<u8>>,
    open_ports:  Vec<String>,
}



impl PortScanner {

    pub fn new(args: PortScanArgs) -> Self {
        let iface = IfaceInfo::iface_name_from_ip(args.target_ip.clone());
        Self {
            my_ip:       IfaceInfo::iface_ip(&iface),
            rand:        RandValues::new(),
            raw_packets: Vec::new(),
            open_ports:  Vec::new(),
            args,
            iface,
        }
    }



    pub fn execute(&mut self) {
        if self.args.udp {
            self.perform_udp_scan();
        } else {
            self.perform_tcp_scan();
        }
    }



    fn perform_tcp_scan(&mut self) {
        self.send_and_receive_tcp();
        self.process_raw_tcp_packets();
        self.display_tcp_result();
    }



    fn send_and_receive_tcp(&mut self) {
        let mut pkt_tools = self.setup_tools();
        let mut iters     = self.setup_tcp_iterators();

        pkt_tools.sniffer.start();
        self.send_tcp_probes(&mut pkt_tools, &mut iters);
        
        thread::sleep(Duration::from_secs(5));
        pkt_tools.sniffer.stop();
        
        self.raw_packets = pkt_tools.sniffer.get_packets();
    }



    fn setup_tcp_iterators(&self) -> TcpIterators {
        let ports  = PortIter::new(&self.args.ports, self.args.random.clone());
        let delays = DelayIter::new(&self.args.delay, ports.len());
        let ip     = self.args.target_ip.to_string();
        TcpIterators { ports, delays, ip }
    }



    fn send_tcp_probes(&mut self, pkt_tools: &mut PacketTools, iters: &mut TcpIterators) {
        for (port, delay) in iters.ports.by_ref().zip(iters.delays.by_ref())  {

            let src_port = self.rand.get_random_port();
            let pkt      = pkt_tools.builder.tcp_ip(self.my_ip, src_port, self.args.target_ip, port);
            pkt_tools.socket.send_to(pkt, self.args.target_ip);

            Self::display_progress(&iters.ip, port, delay);
            thread::sleep(Duration::from_secs_f32(delay));
        }
        println!("");
    }



    fn process_raw_tcp_packets(&mut self) {
        let tcp_packets = mem::take(&mut self.raw_packets);

        for packet in tcp_packets.into_iter() {
            let port = PacketDissector::get_tcp_src_port(&packet);
            self.open_ports.push(port);
        }
    }



    fn display_tcp_result(&self) {
        let device_name = get_host_name(&self.args.target_ip.to_string());
        let ports       = self.open_ports.join(", ");

        println!("\nOpen ports from {} ({})", device_name, self.args.target_ip);
        println!("{}", ports);
    }



    fn perform_udp_scan(&mut self) {
        self.send_and_receive_udp();
        self.process_raw_udp_packets();
        self.display_udp_result();
    }



    fn send_and_receive_udp(&mut self) {
        let mut pkt_tools = self.setup_tools();
        let mut iters     = self.setup_udp_iterators();

        pkt_tools.sniffer.start();
        self.send_udp_probes(&mut pkt_tools, &mut iters);
        
        thread::sleep(Duration::from_secs(5));
        pkt_tools.sniffer.stop();

        self.raw_packets = pkt_tools.sniffer.get_packets();
    }



    fn setup_udp_iterators(&self) -> UdpIterators {
        let ports  = UdpPayloads::new();
        let delays = DelayIter::new(&self.args.delay, ports.len());
        let ip     = self.args.target_ip.to_string();
        UdpIterators {ports, delays, ip}
    }



    fn send_udp_probes(&mut self, pkt_tools: &mut PacketTools, iters: &mut UdpIterators) {
        for ((port, payload), delay) in iters.ports.iter().zip(iters.delays.by_ref())  {

            let src_port = self.rand.get_random_port();
            let pkt      = pkt_tools.builder.udp_ip(
                self.my_ip, src_port, self.args.target_ip, port, payload.data.clone()
            );
            pkt_tools.socket.send_to(pkt, self.args.target_ip);

            Self::display_progress(&iters.ip, port, delay);
            thread::sleep(Duration::from_secs_f32(delay));
        }
        println!("");
    }



    fn process_raw_udp_packets(&mut self) {
        let udp_packets = mem::take(&mut self.raw_packets);
        let payloads    = UdpPayloads::new();

        for packet in udp_packets.into_iter() {
            let port_str  = PacketDissector::get_udp_src_port(&packet);
            let port: u16 = port_str.parse().unwrap();
            let info      = payloads.get(port);
            let result    = format!("{:<5} - {}", port_str, info.unwrap().description); 
            self.open_ports.push(result);
        }
    }



    fn display_udp_result(&self) {
        let device_name = get_host_name(&self.args.target_ip.to_string());

        println!("\nOpen ports from {} ({})", device_name, self.args.target_ip);
        for p in &self.open_ports {
            println!("{}", p);
        }
    }



    fn setup_tools(&self) -> PacketTools {
        PacketTools {
            sniffer: PacketSniffer::new(self.iface.clone(), self.get_bpf_filter()),
            builder: PacketBuilder::new(),
            socket:  Layer3RawSocket::new(&self.iface),
        }
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


    
    fn display_progress(ip: &str, port: u16, delay: f32) {
        let msg = format!("Packet sent to {} port {:<5} - delay: {:.2}", ip, port, delay);
        inline_display(msg);
    }

}