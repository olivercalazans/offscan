use std::net::Ipv4Addr;
use crate::pkt_builder::HeaderBuilder;



pub struct UdpPacket;


impl UdpPacket {

    #[inline]
    pub fn udp_ip(
        buffer:   &mut [u8; 347],
        src_ip:   Ipv4Addr,
        src_port: u16,
        dst_ip:   Ipv4Addr,
        dst_port: u16,
        payload:  &[u8]
        ) -> usize 
    {
        let len_payload: usize = payload.len().try_into().unwrap();
        let len_pkt:     usize = 28 + len_payload;
        
        buffer[28..len_pkt].copy_from_slice(&payload);

        HeaderBuilder::udp(
            &mut buffer[20..len_pkt],
            src_ip, src_port,
            dst_ip, dst_port, len_payload as u16
        );
        
        HeaderBuilder::ip(&mut buffer[..20], len_pkt as u16, 17, src_ip, dst_ip);

        len_pkt
    }



    #[inline]
    pub fn udp_ether(
        buffer:   &mut [u8; 347],
        src_mac:  [u8; 6],
        src_ip:   Ipv4Addr,
        src_port: u16,
        dst_mac:  [u8; 6],
        dst_ip:   Ipv4Addr,
        dst_port: u16,
        payload:  &[u8],
        ) -> usize
    {
        let len_payload: usize = payload.len();
        let len_pkt:     usize = 42 + len_payload;

        buffer[42..len_pkt].copy_from_slice(&payload);

        HeaderBuilder::udp(
            &mut buffer[34..len_pkt], 
            src_ip, src_port, 
            dst_ip, dst_port, len_payload as u16
        );
        HeaderBuilder::ip(&mut buffer[14..34], 28 + len_payload as u16, 17, src_ip, dst_ip);
        HeaderBuilder::ether(&mut buffer[..14], src_mac, dst_mac);

        len_pkt
    }

}