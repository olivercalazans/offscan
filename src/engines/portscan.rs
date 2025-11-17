use std::{thread, time::Duration, mem, net::Ipv4Addr};
use crate::arg_parser::PortScanArgs;
use crate::generators::{DelayIter, PortIter, RandValues};
use crate::iface::IfaceInfo;
use crate::pkt_builder::{PacketBuilder, UdpPayloads};
use crate::sniffer::PacketSniffer;
use crate::sockets::Layer3RawSocket;
use crate::dissectors::PacketDissector;
use crate::utils::{inline_display, get_host_name};



pub struct PortScanner {
    args:        PortScanArgs,
    iface:       String,
    my_ip:       Ipv4Addr,
    raw_packets: Vec<Vec<u8>>,
    open_ports:  Vec<String>,
}



impl PortScanner {

    pub fn new(args: PortScanArgs) -> Self {
        let iface = IfaceInfo::iface_name_from_ip(args.target_ip.clone());
        Self {
            my_ip:       IfaceInfo::iface_ip(&iface),
            raw_packets: Vec::new(),
            open_ports:  Vec::new(),
            args,
            iface,
        }
    }



    pub fn execute(&mut self) {
        if self.args.udp {
            self.send_and_receive_udp();
        } else {
            self.send_and_receive_tcp();
        }

        self.process_raw_packets();
        self.display_result();
    }



    fn send_and_receive_tcp(&mut self) {
        let mut tools = self.setup_tools();
        let mut iters = self.setup_tcp_iterators();

        tools.sniffer.start();
        self.send_tcp_probes(&mut tools, &mut iters);
        
        thread::sleep(Duration::from_secs(5));
        tools.sniffer.stop();
        
        self.raw_packets = tools.sniffer.get_packets();
    }



    fn setup_tcp_iterators(&self) -> TcpIterators {
        let ports  = PortIter::new(&self.args.ports, self.args.random.clone());
        let delays = DelayIter::new(&self.args.delay, ports.len());
        let ip     = self.args.target_ip.to_string();
        TcpIterators { ports, delays, ip }
    }



    fn send_tcp_probes(&mut self, tools: &mut PacketTools, iters: &mut TcpIterators) {
        let mut rand = RandValues::new();
        
        iters.ports.by_ref()
            .zip(iters.delays.by_ref())
            .for_each(|(port, delay)| {
                let src_port = rand.get_random_port();
                
                let pkt = tools.builder.tcp_ip(self.my_ip, src_port, self.args.target_ip, port);
                tools.socket.send_to(pkt, self.args.target_ip);

                Self::display_and_sleep(&iters.ip, port, delay);
            });        

        println!("");
    }



    fn send_and_receive_udp(&mut self) {
        let mut tools = self.setup_tools();
        let mut iters = self.setup_udp_iterators();

        tools.sniffer.start();
        self.send_udp_probes(&mut tools, &mut iters);
        
        thread::sleep(Duration::from_secs(5));
        tools.sniffer.stop();

        self.raw_packets = tools.sniffer.get_packets();
    }



    fn setup_udp_iterators(&self) -> UdpIterators {
        let ports  = UdpPayloads::new();
        let delays = DelayIter::new(&self.args.delay, ports.len());
        let ip     = self.args.target_ip.to_string();

        UdpIterators {ports, delays, ip}
    }



    fn send_udp_probes(&mut self, tools: &mut PacketTools, iters: &mut UdpIterators) {
        let mut rand = RandValues::new();
        
        iters.ports.iter()
            .zip(iters.delays.by_ref())
            .for_each(|((port, payload), delay)| {
                let src_port = rand.get_random_port();
                
                let pkt = tools.builder.udp_ip(self.my_ip, src_port, self.args.target_ip, port, payload);
                tools.socket.send_to(pkt, self.args.target_ip);
                
                Self::display_and_sleep(&iters.ip, port, delay);
            });
        
        println!("");
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


    
    #[inline]
    fn display_and_sleep(ip: &str, port: u16, delay: f32) {
        let msg = format!("Packet sent to {} port {:<5} - delay: {:.2}", ip, port, delay);
        inline_display(&msg);
        thread::sleep(Duration::from_secs_f32(delay));
    }



    fn process_raw_packets(&mut self) {
        let packets = mem::take(&mut self.raw_packets);

        for packet in packets.into_iter() {
            let port = if self.args.udp {
                PacketDissector::get_udp_src_port(&packet)
            } else {
                PacketDissector::get_tcp_src_port(&packet)
            };

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