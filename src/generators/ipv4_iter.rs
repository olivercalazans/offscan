use std::net::Ipv4Addr;
use crate::utils::abort;



pub struct Ipv4Iter {
    current: u32,
    end: u32,
    start: u32,
    total: u64,
}



impl Ipv4Iter {

    pub fn new(
        cidr:     &str,
        start_ip: Option<Ipv4Addr>,
        end_ip:   Option<Ipv4Addr>,
    ) -> Self {
        let (network_u32, broadcast_u32) = Self::parse_cidr(cidr);
        
        let usable_start = network_u32.saturating_add(1);
        let usable_end = broadcast_u32.saturating_sub(1);
        
        if usable_start > usable_end {
            abort("No usable IP addresses in CIDR (network and broadcast excluded)");
        }

        let start_range = start_ip
            .map(|ip| u32::from_be_bytes(ip.octets()))
            .unwrap_or(usable_start);

        let end_range = end_ip
            .map(|ip| u32::from_be_bytes(ip.octets()))
            .unwrap_or(usable_end);

        if start_range < usable_start || start_range > usable_end {
            abort(&format!(
                "Start IP {} is out of usable range ({}-{})",
                Ipv4Addr::from(start_range.to_be_bytes()),
                Ipv4Addr::from(usable_start.to_be_bytes()),
                Ipv4Addr::from(usable_end.to_be_bytes())
            ));
        }

        if end_range < usable_start || end_range > usable_end {
            abort(&format!(
                "End IP {} is out of usable range ({}-{})",
                Ipv4Addr::from(end_range.to_be_bytes()),
                Ipv4Addr::from(usable_start.to_be_bytes()),
                Ipv4Addr::from(usable_end.to_be_bytes())
            ));
        }

        if start_range > end_range {
            abort("Start IP cannot be greater than end IP");
        }

        let total = (end_range - start_range + 1) as u64;

        Ipv4Iter {
            current: start_range,
            end:     end_range,
            start:   start_range,
            total,
        }
    }



    fn parse_cidr(cidr: &str) -> (u32, u32) {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            abort(&format!("Invalid CIDR: {}", cidr));
        }

        let ip: Ipv4Addr = parts[0].parse().unwrap_or_else(|e| {
            abort(&format!("Invalid IP in CIDR '{}': {}", cidr, e));
        });

        let prefix: u8 = parts[1].parse::<u8>().unwrap_or_else(|e| {
            abort(&format!("Invalid prefix in CIDR '{}': {}", cidr, e));
        });
        
        if prefix > 32 {
            abort(&format!("Prefix out of range in CIDR '{}': {}", cidr, prefix));
        }

        let ip_u32 = u32::from_be_bytes(ip.octets());
        let network_mask = if prefix == 0 {
            0u32
        } else {
            (!0u32).checked_shl(32 - prefix as u32).unwrap_or(0)
        };
        
        let network_u32   = ip_u32 & network_mask;
        let broadcast_u32 = network_u32 | !network_mask;

        (network_u32, broadcast_u32)
    }



    pub fn reset(&mut self) {
        self.current = self.start;
    }



    pub fn total(&self) -> u64 {
        self.total
    }
}



impl Iterator for Ipv4Iter {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Ipv4Addr> {
        if self.current > self.end {
            return None;
        }
            
        let ip = Ipv4Addr::from(self.current.to_be_bytes());
        self.current += 1;
        Some(ip)
    }
}