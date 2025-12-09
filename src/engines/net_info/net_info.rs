use std::fs;
use crate::iface::IfaceInfo;



pub struct NetworkInfo;


impl NetworkInfo {

    pub fn execute() {
        for (i, iface) in IfaceInfo::iface_names().into_iter().enumerate() {
            let state       = Self::get_state(&iface);
            let if_type     = Self::get_type(&iface);
            let mac         = IfaceInfo::mac(&iface);
            let ip          = Self::get_ip(&iface);
            let cidr        = Self::get_cidr(&iface);
            let host_len    = Self::get_len_host(&cidr);
            let mtu         = Self::get_mtu(&iface);
            let gateway_mac = Self::get_gateway_mac(&iface);
            let gateway_ip  = Self::get_gateway_ip(&iface);

            println!("#{} Interface: {} - State: {}", i, iface, state);
            println!("  - Type.......: {}", if_type);
            println!("  - MAC........: {}", mac);
            println!("  - IP.........: {}", ip);
            println!("  - Net Addr...: {}", cidr);
            println!("  - Len hosts..: {}", host_len);
            println!("  - MTU........: {}", mtu);
            println!("  - Gateway MAC: {}", gateway_mac);
            println!("  - Gateway IP.: {}", gateway_ip);
            println!("")            
        }
    }



    fn get_state(iface: &str) -> String {
        IfaceInfo::get_info("operstate", &iface).to_uppercase()
    }



    fn get_type(iface: &str) -> String {
        let type_path = format!("/sys/class/net/{}/type", iface);

        fs::read_to_string(&type_path)
            .map(|content| {
                match content.trim() {
                    "1"   => "Ethernet".to_string(),
                    "772" => "Loopback".to_string(),
                    "801" => "Wireless".to_string(),
                    code  => format!("Type-{}", code),
                }
            })
            .unwrap_or_else(|_| "Unknown".to_string())
    }



    fn get_ip(iface: &str) -> String {
        match IfaceInfo::iface_ip(iface) {
            Ok(ip) => ip.to_string(),
            Err(_) => "None".to_string(),
        }
    }



    fn get_cidr(iface: &str) -> String {
        match IfaceInfo::iface_cidr(iface) {
            Ok(ip) => ip.to_string(),
            Err(_) => "Unknown".to_string(),
        }
    }



    fn get_len_host(cidr: &str) -> String {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return "None".to_string();
        }

        let cidr_value: u8 = match parts[1].parse() {
            Ok(value) => value,
            Err(_)    => return "Unknown".to_string(),
        };

        if cidr_value > 32 {
            return "None".to_string();
        }

        let host_bits   = 32 - cidr_value;
        let total_hosts = 2u32.pow(host_bits as u32);

        if cidr_value >= 31 {
            return total_hosts.to_string();
        }
        
        (total_hosts - 2).to_string()
    }



    fn get_mtu(iface: &str) -> String {
        IfaceInfo::get_info("mtu", &iface)
    }



    fn get_gateway_mac(iface: &str) -> String {
        match IfaceInfo::gateway_mac(iface) {
            Ok(mac) => { mac },
            Err(_)  => { "Unknown".to_string() }
        }
    }



    fn get_gateway_ip(iface: &str) -> String {
        let content = fs::read_to_string("/proc/net/route")
            .unwrap_or_default();
        
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() < 8 || parts[0] != iface {
                continue;
            }

            let gateway_hex = parts[2];
            if gateway_hex == "00000000" {
                continue;
            }

            if let Some(gateway) = Self::hex_to_ip(gateway_hex) {
                return gateway;
            }
        }

        "Unknown".to_string()
    }



    fn hex_to_ip(hex: &str) -> Option<String> {
        if hex.len() != 8 {
            return None;
        }

        let bytes: Vec<u8> = (0..4)
            .map(|i| u8::from_str_radix(&hex[i*2..i*2+2], 16).ok())
            .collect::<Option<Vec<_>>>()?;

        Some(format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0]))
    }

}