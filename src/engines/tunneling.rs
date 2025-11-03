use std::{net::Ipv4Addr, thread, time::Duration};
use crate::arg_parser::{TunnelArgs, parse_mac};
use crate::generators::RandValues;
use crate::iface::IfaceInfo;
use crate::pkt_kit::{PacketBuilder, Layer2RawSocket, Layer3RawSocket, PacketSniffer, PacketDissector};
use crate::utils::abort;



struct PacketInfo {
    src_mac: [u8; 6],
    src_ip:  Ipv4Addr,
    dst_mac: [u8; 6],
    dst_ip:  Ipv4Addr,
}



pub struct ProtocolTunneler {
    args:        TunnelArgs,
    pkt_builder: PacketBuilder,
    rand:        RandValues,
    socket:      Layer2RawSocket,
}



impl ProtocolTunneler {

    pub fn new(args: TunnelArgs) -> Self {
        Self {
            socket:      Layer2RawSocket::new(&args.iface),
            pkt_builder: PacketBuilder::new(),
            rand:        RandValues::new(),
            args,
        }
    }



    pub fn execute(&mut self) {
        let pkt_info = self.set_pkt_info();
        self.send_tcp_over_udp(&pkt_info);
    }



    fn set_pkt_info(&mut self) -> PacketInfo {
        let src_ip  = self.args.src_ip.unwrap_or_else(|| IfaceInfo::iface_ip(&self.args.iface));
        let src_mac = self.args.src_mac.unwrap_or_else(|| self.resolve_mac(src_ip));
        let dst_ip  = Ipv4Addr::new(8, 8, 8, 8);
        let dst_mac = self.resolve_mac(dst_ip);
        PacketInfo { src_mac, src_ip, dst_mac, dst_ip }
    }



    fn resolve_mac(&mut self, target_ip: Ipv4Addr) -> [u8; 6] {
        let (mut sniffer, socket) = self.setup_tools(target_ip);
        
        sniffer.start();
        self.send_icmp_probes(socket, target_ip);

        thread::sleep(Duration::from_secs(3));
        sniffer.stop();

        let raw_packets = sniffer.get_packets();
        self.process_raw_packets(raw_packets)
    }



    fn setup_tools(&self, target_ip: Ipv4Addr) -> (PacketSniffer, Layer3RawSocket) {
        let filter  = self.get_bpf_filter(target_ip);
        let sniffer = PacketSniffer::new(self.args.iface.clone(), filter, false);
        let socket  = Layer3RawSocket::new(&self.args.iface);
        (sniffer, socket)
    }



    fn send_icmp_probes(&mut self, socket: Layer3RawSocket, target_ip: Ipv4Addr) {
        let my_ip = IfaceInfo::iface_ip(&self.args.iface);
        let pkt   = self.pkt_builder.icmp_echo_req(my_ip, target_ip);
        
        socket.send_to(pkt, target_ip);
        thread::sleep(Duration::from_secs(1));
        socket.send_to(pkt, target_ip);
    }



    fn process_raw_packets(&self, packets: Vec<Vec<u8>>) -> [u8; 6] {
        if packets.len() < 1 { abort("Impossible to resolve MAC. try again or set a MAC address")}
        let mac = PacketDissector::get_src_mac(&packets[0]);
        parse_mac(&mac).unwrap()
    }



    fn get_bpf_filter(&self, target_ip: Ipv4Addr) -> String {
        format!("src host {}", target_ip)
    }



    fn send_tcp_over_udp(&mut self, pkt_info: &PacketInfo) {
        let pkt = self.pkt_builder.tcp_over_udp(
            pkt_info.src_mac, pkt_info.src_ip, self.rand.get_random_port(), self.rand.get_random_port(),
            pkt_info.dst_mac, pkt_info.dst_ip, 53, 80
        );
        self.socket.send(pkt);
        println!(
            "> TCP over UDP packet sent.\n\tFrom IP: {:<15} MAC: {}\n\tTo   IP: {:<15} MAC: {}",
            pkt_info.src_ip, Self::format_mac(pkt_info.src_mac),
            pkt_info.dst_ip, Self::format_mac(pkt_info.dst_mac)
        );
    }


    fn format_mac(mac: [u8; 6]) -> String {
        mac.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

}
