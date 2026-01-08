use std::net::Ipv4Addr;
use crate::utils::abort;



#[derive(Clone)]
pub(crate) struct Ipv4Iter {
    current : u32,
    end     : u32,
    total   : u64,
    pub start_u32 : u32,
    pub end_u32   : u32,
}


#[derive(Default)]
struct TempData {
    range               : String,
    cidr_has_usable_ips : bool,
    usable_start        : u32,
    usable_end          : u32,
    start_part          : String,
    end_part            : String,
    start_ip            : Option<u32>,
    end_ip              : Option<u32>,
    start_in_cidr       : bool,
    end_in_cidr         : bool,
}


impl Ipv4Iter {
    
    pub fn new(cidr: &str, range: Option<&str>) -> Self {
        let mut data = TempData::default();

        let (network_u32, broadcast_u32) = Self::parse_cidr(cidr);
        
        data.usable_start        = network_u32.saturating_add(1);
        data.usable_end          = broadcast_u32.saturating_sub(1);
        data.cidr_has_usable_ips = data.usable_start <= data.usable_end;
        
        let (start_range, end_range) = if let Some(range_str) = range {
            data.range = range_str.trim().to_string();
            Self::parse_range(&mut data)
        } else {
            if data.cidr_has_usable_ips {
                (data.usable_start, data.usable_end)
            } else {
                (network_u32, network_u32)
            }
        };

        if start_range > end_range {
            abort("Start IP cannot be greater than end IP");
        }

        let total = (end_range - start_range + 1) as u64;

        Ipv4Iter {
            current   : start_range,
            end       : end_range,
            start_u32 : start_range,
            end_u32   : end_range,
            total,
        }
    }



    fn parse_cidr(cidr: &str) -> (u32, u32) {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            abort(&format!("Invalid CIDR: {}", cidr));
        }

        let ip: Ipv4Addr = parts[0].parse()
            .unwrap_or_else(|e| {
                abort(&format!("Invalid IP in CIDR '{}': {}", cidr, e));
        });

        let prefix: u8 = parts[1].parse::<u8>()
            .unwrap_or_else(|e| {
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



    fn parse_range(data: &mut TempData) -> (u32, u32) {
        if data.range.is_empty() {
            abort("Range string cannot be empty");
        }

        if data.range.contains('*') {
            Self::parse_wildcard_range(data)
        } else {
            Self::parse_single_ip_range(data)
        }
    }



    fn parse_single_ip_range(data: &TempData) -> (u32, u32) {
        let ip     = Self::parse_ip_address(&data.range);
        let ip_u32 = u32::from_be_bytes(ip.octets());
        (ip_u32, ip_u32)
    }

    
    
    fn parse_wildcard_range(data: &mut TempData) -> (u32, u32) {
        let (start_part, end_part) = Self::split_wildcard_parts(data);
        data.start_part            = start_part.clone();
        data.end_part              = end_part.clone();

        let (start_ip, start_in_cidr) = Self::parse_ip_part(data, &start_part);
        data.start_ip                 = start_ip;
        data.start_in_cidr            = start_in_cidr;

        let (end_ip, end_in_cidr) = Self::parse_ip_part(data, &end_part);
        data.end_ip               = end_ip;
        data.end_in_cidr          = end_in_cidr;

        Self::determine_range_bounds(data)
    }

    
    
    fn split_wildcard_parts(data: &TempData) -> (String, String) {
        let parts: Vec<&str> = data.range.split('*').collect();

        if parts.len() != 2 {
            abort(&format!("Invalid range format: {}", data.range));
        }

        (parts[0].trim().to_string(), parts[1].trim().to_string())
    }

    
    
    fn parse_ip_part(data: &TempData, ip_str: &str) -> (Option<u32>, bool) {
        if ip_str.is_empty() {
            return (None, false);
        }

        let ip      = Self::parse_ip_address(ip_str);
        let ip_u32  = u32::from_be_bytes(ip.octets());
        let in_cidr = 
            data.cidr_has_usable_ips && 
            ip_u32 >= data.usable_start && 
            ip_u32 <= data.usable_end;

        (Some(ip_u32), in_cidr)
    }

    
    
    fn parse_ip_address(ip_str: &str) -> Ipv4Addr {
        ip_str.parse().unwrap_or_else(|e| {
            abort(&format!("Invalid IP address '{}': {}", ip_str, e));
        })
    }



    fn determine_range_bounds(data: &mut TempData) -> (u32, u32) {
        match (data.start_part.is_empty(), data.end_part.is_empty()) {
            (false, false) => { Self::get_start_and_end_ip(data) },
            (false, true)  => { Self::get_start_ip_and_usable_end(data) },
            (true,  false) => { Self::get_usable_start_and_end_ip(data) },
            (true,  true)  => { Self::get_usable_start_and_end(data) },
        }
    }



    fn get_start_and_end_ip(data: &TempData) -> (u32, u32) {
        let start_ip = data.start_ip.clone();
        let end_ip   = data.end_ip.clone();

        (start_ip.unwrap(), end_ip.unwrap())
    }



    fn get_start_ip_and_usable_end(data: &mut TempData) -> (u32, u32) {
        let ip = data.start_ip.clone();

        if !data.start_in_cidr {
            let ip_u32 = ip.unwrap();
            
            abort(&format!(
                "Start IP {} is outside CIDR range. When using 'IP*', the IP must be within the CIDR",
                Ipv4Addr::from(ip_u32.to_be_bytes())
            ));
        }
        
        (ip.unwrap(), data.usable_end.clone())
    }



    fn get_usable_start_and_end_ip(data: &TempData) -> (u32, u32) {
        let ip = data.end_ip.clone();

        if !data.end_in_cidr {
            let ip_u32 = ip.unwrap();
            
            abort(&format!(
                "End IP {} is outside CIDR range. When using '*IP', the IP must be within the CIDR.",
                Ipv4Addr::from(ip_u32.to_be_bytes())
            ));
        }
        
        (data.usable_start.clone(), ip.unwrap())
    }



    fn get_usable_start_and_end(data: &TempData) -> (u32, u32) {
        if data.cidr_has_usable_ips {
            return (data.usable_start.clone(), data.usable_end.clone());
        }
        
        (data.usable_start.clone(), data.usable_start.clone())
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