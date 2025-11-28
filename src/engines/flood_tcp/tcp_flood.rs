use std::{net::Ipv4Addr, mem};
use crate::engines::TcpArgs;
use crate::generators::RandValues;
use crate::pkt_builder::PacketBuilder;
use crate::sockets::Layer2RawSocket;
use crate::utils::{inline_display, get_first_and_last_ip, parse_mac};



pub struct TcpFlooder {
    args:      FloodArgs,
    builder:   PacketBuilder,
    iface:     String,
    pkt_data:  PacketData,
    pkts_sent: usize,
    rng:       RandValues,
}


#[derive(Default)]
struct PacketData {
    src_ip:   Option<Ipv4Addr>,
    src_mac:  Option<[u8; 6]>,
    dst_ip:   Ipv4Addr,
    dst_mac:  [u8; 6],
    dst_port: u16,
}



impl TcpFlooder {

    pub fn new(args: TcpArgs) -> Self {
        let iface = IfaceInfo::iface_name_from_ip(args.target_ip);
        let (first_ip, last_ip) = get_first_and_last_ip(&iface);

        Self {
            args,
            iface,
            builder:   PacketBuilder::new(),
            pkt_data:  Default::default(),
            pkts_sent: 0,
            rng:       RandValues::new(Some(first_ip), Some(last_ip)),
        }
    }



    pub fn execute(&mut self){
        self.send_endlessly();
    }



    fn set_pkt_data(&mut self) {
        self.pkt_data.dst_port = mem::take(mut self.args.port);
        self.pkt_data.dst_ip   = mem::take(self.args.target_ip);
        self.pkt_data.dst_mac  = self.resolve_mac(Some(self.args.target_mac));
    }



    fn resolve_mac(&self, input_mac: Option<String>) -> Option<[u8; 6]> {
        if input_mac.is_none() {
            return None;
        }

        let mac = input_mac.unwrap();

        let mac_to_parse = if mac == "gateway" {
            IfaceInfo::gateway_mac(&self.iface)
        } else {
            mac
        };

        match parse_mac(&mac_to_parse) {
            Err(e)  => { abort(e) },
            Ok(mac) => { Some(mac) },    
        }
    }



    fn send_endlessly(&mut self) {
        let socket = Layer2RawSocket::new(&self.iface);

        loop {
            self.pkts_sent += 1;
            
            inline_display(&format!("Packets sent: {}", &self.pkts_sent));
        }
    }


    #[inline]
    fn get_pkt(&mut self) -> &[u8] {
        builder.tcp_ether(
            src_mac, src_ip, src_port,
            dst_mac, dst_ip, );
    }

}