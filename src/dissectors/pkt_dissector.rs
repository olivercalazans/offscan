use std::net::Ipv4Addr;



pub struct PacketDissector {
    pkt: Vec<u8>,
}


impl PacketDissector {

    pub fn new() -> Self {
        Self { pkt: Vec::new() }
    }



    #[inline]
    pub fn update_pkt(&mut self, raw_pkt: Vec<u8>) {
        self.pkt = raw_pkt;
    }



    #[inline]
    fn is_ipv4(&self) -> bool {
        if self.pkt.len() < 14 {
            return false;
        }

        let ethertype = u16::from_be_bytes([self.pkt[12], self.pkt[13]]);

        ethertype == 0x0800
    }



    #[inline]
    fn ihl(&self) -> Option<u8> {
        if self.pkt.len() < 15 {
            return None;
        }

        let ihl = self.pkt[14] & 0x0f;
        
        if ihl < 5 {
            return None;
        }

        Some(ihl)
    }



    #[inline]
    fn ip_header_len(&self) -> Option<usize> {
        let ihl        = self.ihl()?;
        let header_len = (ihl as usize) * 4;
        Some(14 + header_len)
    }



    #[inline]
    fn is_tcp(&self) -> bool {
        if self.pkt.len() < 24 {
            return false;
        }

        self.pkt[23] == 6
    }



    #[inline]
    fn is_udp(&self) -> bool {
        if self.pkt.len() < 24 {
            return false;
        }

        self.pkt[23] == 17 
    }



    #[inline]
    pub fn get_src_mac(&self) -> Option<String> {
        if self.pkt.len() < 12 {
            return None;
        }

        let mac = self.pkt[6..12]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        
        Some(mac)
    }



    #[inline]
    pub fn get_src_ip(&self) -> Option<Ipv4Addr> {
        if self.pkt.len() < 30 || !self.is_ipv4() {
            return None;
        }

        let src_ip_bytes: [u8; 4] = [
            self.pkt[26], self.pkt[27], 
            self.pkt[28], self.pkt[29]
        ];

        Some(Ipv4Addr::from(src_ip_bytes))
    }



    #[inline]
    pub fn get_tcp_src_port(&self) -> Option<u16> {
        if self.pkt.len() < 54 || !self.is_ipv4() || !self.is_tcp() {
            return None;
        }

        let ip_payload_start = self.ip_header_len()?;

        if self.pkt.len() < ip_payload_start + 2 {
            return None;
        }

        Some(u16::from_be_bytes([self.pkt[ip_payload_start], self.pkt[ip_payload_start + 1]]))
    }



    #[inline]
    pub fn get_udp_src_port(&self) -> Option<u16> {
        if self.pkt.len() < 42 || !self.is_ipv4() || !self.is_udp() {
            return None;
        }

        let ip_payload_start = self.ip_header_len()?;

        if self.pkt.len() < ip_payload_start + 2 {
            return None;
        }

        Some(u16::from_be_bytes([
            self.pkt[ip_payload_start],
            self.pkt[ip_payload_start + 1]
        ]))
    }

}