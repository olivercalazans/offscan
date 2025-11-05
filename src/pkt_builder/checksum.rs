use std::net::Ipv4Addr;



pub fn tcp_udp_checksum(packet: &[u8], src_ip: &Ipv4Addr, dst_ip: &Ipv4Addr, protocol: u8) -> u16 {
    let mut sum = 0u32;

    let src_octets = src_ip.octets();
    let dst_octets = dst_ip.octets();

    sum += ((src_octets[0] as u32) << 8 | src_octets[1] as u32)
         + ((src_octets[2] as u32) << 8 | src_octets[3] as u32);
    sum += ((dst_octets[0] as u32) << 8 | dst_octets[1] as u32)
         + ((dst_octets[2] as u32) << 8 | dst_octets[3] as u32);

    sum += protocol as u32;
    sum += packet.len() as u32;

    let mut i = 0;
    while i + 1 < packet.len() {
        sum += ((packet[i] as u32) << 8) | packet[i + 1] as u32;
        i += 2;
    }

    if i < packet.len() {
        sum += (packet[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}



pub fn icmp_checksum(packet: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;

    while i + 1 < packet.len() {
        sum += ((packet[i] as u32) << 8) | (packet[i + 1] as u32);
        i += 2;
    }

    if i < packet.len() {
        sum += (packet[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}



pub fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;

    while i + 1 < header.len() {
        sum += ((header[i] as u32) << 8) | (header[i + 1] as u32);
        i += 2;
    }

    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}