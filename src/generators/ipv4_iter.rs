use std::net::Ipv4Addr;
use crate::utils::abort;



pub struct Ipv4Iter {
    current: u32,
    end:     u32,
    start:   u32,
    total:   u64,
}



impl Ipv4Iter {
    
    pub fn new(cidr: &str, range_str: Option<&str>) -> Self {
        let (network_u32, broadcast_u32) = Self::parse_cidr(cidr);
        
        let usable_start = network_u32.saturating_add(1);
        let usable_end   = broadcast_u32.saturating_sub(1);
        
        let cidr_has_usable_ips = usable_start <= usable_end;
        
        let (start_range, end_range) = if let Some(range) = range_str {
            Self::parse_range(range, cidr_has_usable_ips, usable_start, usable_end)
        } else {
            if cidr_has_usable_ips {
                (usable_start, usable_end)
            } else {
                (network_u32, network_u32)
            }
        };

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



    fn parse_range(
        range_str:           &str, 
        cidr_has_usable_ips: bool,
        usable_start:        u32, 
        usable_end:          u32
        ) -> (u32, u32)
    {
        let range_str = range_str.trim();
        
        if range_str.is_empty() {
            abort("Range string cannot be empty");
        }
        
        if range_str.contains('*') {
            let parts: Vec<&str> = range_str.split('*').collect();
            
            if parts.len() != 2 {
                abort(&format!("Invalid range format: {}", range_str));
            }
            
            let start_str = parts[0].trim();
            let end_str   = parts[1].trim();
            
            let mut start_ip = None;
            let mut end_ip   = None;
            let mut start_is_in_cidr = false;
            let mut end_is_in_cidr   = false;
            
            if !start_str.is_empty() {
                let ip: Ipv4Addr = start_str.parse().unwrap_or_else(|e| {
                    abort(&format!("Invalid start IP '{}': {}", start_str, e));
                });
                let ip_u32       = u32::from_be_bytes(ip.octets());
                start_ip         = Some(ip_u32);
                start_is_in_cidr = cidr_has_usable_ips && ip_u32 >= usable_start && ip_u32 <= usable_end;
            }
            
            if !end_str.is_empty() {
                let ip: Ipv4Addr = end_str.parse().unwrap_or_else(|e| {
                    abort(&format!("Invalid end IP '{}': {}", end_str, e));
                });

                let ip_u32     = u32::from_be_bytes(ip.octets());
                end_ip         = Some(ip_u32);
                end_is_in_cidr = cidr_has_usable_ips && ip_u32 >= usable_start && ip_u32 <= usable_end;
            }
            
            match (start_str.is_empty(), end_str.is_empty()) {
                (false, false) => {
                    (start_ip.unwrap(), end_ip.unwrap())
                }

                (false, true) => {
                    if !start_is_in_cidr {
                        abort(&format!(
                            "Start IP {} is outside CIDR range. When using 'IP*', the IP must be within the CIDR.",
                            Ipv4Addr::from(start_ip.unwrap().to_be_bytes())
                        ));
                    }
                    (start_ip.unwrap(), usable_end)
                }

                (true, false) => {
                    if !end_is_in_cidr {
                        abort(&format!(
                            "End IP {} is outside CIDR range. When using '*IP', the IP must be within the CIDR.",
                            Ipv4Addr::from(end_ip.unwrap().to_be_bytes())
                        ));
                    }
                    (usable_start, end_ip.unwrap())
                }

                (true, true) => {
                    if cidr_has_usable_ips {
                        (usable_start, usable_end)
                    } else {
                        (usable_start, usable_start)
                    }
                }
            }
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