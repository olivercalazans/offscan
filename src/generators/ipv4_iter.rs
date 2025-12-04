use std::net::Ipv4Addr;
use crate::utils::abort;



pub struct Ipv4Iter {
    current: u32,
    end: u32,
    start: u32,
    total: u64,
}



impl Ipv4Iter {

    pub fn new(cidr: &str, range_str: Option<&str>) -> Self {
        let (network_u32, broadcast_u32) = Self::parse_cidr(cidr);
        
        let usable_start = network_u32.saturating_add(1);
        let usable_end   = broadcast_u32.saturating_sub(1);
        
        if usable_start > usable_end {
            abort("No usable IP addresses in CIDR (network and broadcast excluded)");
        }

        let (start_range, end_range) = if let Some(range) = range_str {
            Self::parse_range(range)
        } else {
            (usable_start, usable_end)
        };

        if start_range > end_range {
            abort("Start IP cannot be greater than end IP");
        }

        let total = (end_range - start_range + 1) as u64;

        Ipv4Iter {
            current: start_range,
            end: end_range,
            start: start_range,
            total,
        }
    }



    fn parse_range(range_str: &str) -> (u32, u32) {
        let range_str = range_str.trim();
        
        if range_str.contains('-') {
            let parts: Vec<&str> = range_str.split('-').collect();
            
            if parts.len() != 2 {
                abort(&format!("Invalid range format: {}", range_str));
            }
            
            let start_str = parts[0].trim();
            let end_str   = parts[1].trim();
            
            if start_str.is_empty() || end_str.is_empty() {
                abort("Range format must include both start and end IPs when using hyphen");
            }
            
            let start_ip: Ipv4Addr = start_str.parse().unwrap_or_else(|e| {
                abort(&format!("Invalid start IP '{}': {}", start_str, e));
            });
            
            let end_ip: Ipv4Addr = end_str.parse().unwrap_or_else(|e| {
                abort(&format!("Invalid end IP '{}': {}", end_str, e));
            });
            
            let start_u32 = u32::from_be_bytes(start_ip.octets());
            let end_u32 = u32::from_be_bytes(end_ip.octets());
            
            if start_u32 > end_u32 {
                abort("Start IP cannot be greater than end IP");
            }
            
            (start_u32, end_u32)

        } else {

            let ip: Ipv4Addr = range_str.parse().unwrap_or_else(|e| {
                abort(&format!("Invalid IP address '{}': {}", range_str, e));
            });
            let ip_u32 = u32::from_be_bytes(ip.octets());
            
            (ip_u32, ip_u32)
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