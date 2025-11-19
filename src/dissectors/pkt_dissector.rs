pub struct PacketDissector;


impl PacketDissector {

    pub fn get_udp_src_port(packet: &[u8]) -> Option<u16> {
        if packet.len() < 42 {
            return None;
        }

        let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
        if ethertype != 0x0800 {
            return None;
        }

        let ip_protocol = packet[23];
        if ip_protocol != 17 {
            return None;
        }

        Some(u16::from_be_bytes([packet[34], packet[35]]))
    }



    pub fn get_tcp_src_port(packet: &[u8]) -> Option<u16> {
        if packet.len() < 38 {
            return None;
        }

        if u16::from_be_bytes([packet[12], packet[13]]) != 0x0800 {
            return None;
        }

        let ihl = packet[14] & 0x0f;
        if ihl < 5 {
            return None;
        }
        let ip_header_len    = (ihl as usize) * 4;
        let ip_payload_start = 14 + ip_header_len;

        if packet[23] != 6 {
            return None;
        }

        if packet.len() < ip_payload_start + 2 {
            return None;
        }

        Some(u16::from_be_bytes([packet[ip_payload_start], packet[ip_payload_start + 1]]))
    }



    pub fn get_src_ip(packet: &[u8]) -> String {
        if packet.len() < 30 {
            return "small packet".into();
        }

        let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
        if ethertype != 0x0800 {
            return "not ipv4".into();
        }

        let src = &packet[26..30];
        format!("{}.{}.{}.{}", src[0], src[1], src[2], src[3])
    }



    pub fn get_src_mac(packet: &[u8]) -> String {
        if packet.len() < 12 {
            return "small packet".into();
        }

        packet[6..12]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

}
