use std::{thread, time::Duration, mem, net::Ipv4Addr};
use crate::arg_parser::PortScanArgs;
use crate::generators::{DelayIter, PortIter, RandValues};
use crate::iface::IfaceInfo;
use crate::pkt_builder::PacketBuilder;
use crate::sniffer::PacketSniffer;
use crate::sockets::Layer3RawSocket;
use crate::dissectors::PacketDissector;
use crate::utils::{inline_display, get_host_name};



struct PacketTools {
    sniffer: PacketSniffer,
    builder: PacketBuilder,
    socket:  Layer3RawSocket,
}



struct Iterators {
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
        self.send_and_receive();
        self.process_raw_packets();
        self.display_result();
    }



    fn send_and_receive(&mut self) {
        let mut pkt_tools = self.setup_tools();
        let mut iters     = self.setup_iterators();

        pkt_tools.sniffer.start();
        self.send_probes(&mut pkt_tools, &mut iters);
        
        thread::sleep(Duration::from_secs(3));
        pkt_tools.sniffer.stop();
        
        self.raw_packets = pkt_tools.sniffer.get_packets();
    }



    fn setup_tools(&self) -> PacketTools {
        PacketTools {
            sniffer: PacketSniffer::new(self.iface.clone(), self.get_bpf_filter()),
            builder: PacketBuilder::new(),
            socket:  Layer3RawSocket::new(&self.iface),
        }
    }



    fn get_bpf_filter(&self) -> String {
        format!("tcp[13] & 0x12 == 0x12 and src host {}", self.args.target_ip)
    }



    fn setup_iterators(&self) -> Iterators {
        let ports  = PortIter::new(&self.args.ports, self.args.random.clone());
        let delays = DelayIter::new(&self.args.delay, ports.len());
        let ip     = self.args.target_ip.to_string();
        Iterators {ports, delays, ip}
    }



    fn send_probes(&mut self, pkt_tools: &mut PacketTools, iters: &mut Iterators) {
        for (port, delay) in iters.ports.by_ref().zip(iters.delays.by_ref())  {

            let src_port = self.rand.get_random_port();
            let pkt      = pkt_tools.builder.tcp_ip(self.my_ip, src_port, self.args.target_ip, port);
            pkt_tools.socket.send_to(pkt, self.args.target_ip);

            Self::display_progress(&iters.ip, port, delay);
            thread::sleep(Duration::from_secs_f32(delay));
        }
        println!("");
    }



    fn display_progress(ip: &str, port: u16, delay: f32) {
        let msg = format!("Packet sent to {} port {:<5} - delay: {:.2}", ip, port, delay);
        inline_display(msg);
    }



    fn process_raw_packets(&mut self) {
        self.process_tcp_packets();
    }



    fn process_tcp_packets(&mut self) {
        let tcp_packets = mem::take(&mut self.raw_packets);

        for packet in tcp_packets.into_iter() {
            let port = PacketDissector::get_src_tcp_port(&packet);
            self.open_ports.push(port);
        }
    }



    fn display_result(&self) {
        let device_name = get_host_name(&self.args.target_ip.to_string());
        let ports       = self.open_ports.join(", ");

        println!("\nOpen ports from {} ({})", device_name, self.args.target_ip);
        println!("{}", ports);
    }

}