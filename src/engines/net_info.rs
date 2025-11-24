use std::{collections::HashMap, fs, net::Ipv4Addr};
use crate::iface::IfaceInfo;



pub struct NetworkInfo {
    ifaces: HashMap<String, Info>,
}


struct Info {
    state:    String,
    if_type:  String,
    mac:      String,
    ip:       Ipv4Addr,
    cidr:     String,
    host_len: String,
    mtu:      String,
    gateway:  String,
}



impl NetworkInfo {

    pub fn new() -> Self {
        Self { ifaces: HashMap::new(), }
    }


    pub fn execute(&mut self) {
        self.get_iface_info();
        self.display_result();
    }


    fn get_iface_info(&mut self) {
        for iface in IfaceInfo::get_iface_names() {
            let state    = Self::get_info("operstate", &iface).to_uppercase();
            let if_type  = Self::get_iface_type(&iface);
            let ip       = IfaceInfo::iface_ip(&iface);
            let mac      = Self::get_info("address", &iface);
            let mtu      = Self::get_info("mtu", &iface);
            let gateway  = Self::get_gateway(&iface);
            let cidr     = IfaceInfo::iface_network_cidr(&iface);
            let host_len = Self::calculate_hosts_from_cidr(&cidr);

            let info = Info{
                state, if_type, ip, mac, mtu, gateway, cidr, host_len
            };
            
            self.ifaces.insert(iface, info);
        }
    }



    fn get_info(info_type: &str, iface: &str) -> String {
        let info = format!("/sys/class/net/{}/{}", iface, info_type);
        
        fs::read_to_string(&info)
            .map(|content| content.trim().to_string())
            .unwrap_or_else(|_| "Unknown".to_string())
    }



    pub fn get_iface_type(iface: &str) -> String {
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



    fn get_gateway(iface: &str) -> String {
        let content = fs::read_to_string("/proc/net/route")
            .unwrap_or_default();
        
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() >= 8 && parts[0] == iface {
                let gateway_hex = parts[2];
                if gateway_hex != "00000000" {
                    if let Some(gateway) = Self::hex_to_ip(gateway_hex) {
                        return gateway;
                    }
                }
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



    pub fn calculate_hosts_from_cidr(cidr: &str) -> String {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return "Unknown".to_string();
        }

        let cidr_value: u8 = match parts[1].parse() {
            Ok(value) => value,
            Err(_)    => return "Unknown".to_string(),
        };

        if cidr_value > 32 {
            return "Unknown".to_string();
        }

        let host_bits   = 32 - cidr_value;
        let total_hosts = 2u32.pow(host_bits as u32);

        if cidr_value >= 31 {
            return total_hosts.to_string();
        }
        
        (total_hosts - 2).to_string()
    }



    fn display_result(&self) {
        for (name, info) in &self.ifaces {
            println!("Interface: {} - State: {}", name, info.state);
            println!("\tType.....: {}", info.if_type);
            println!("\tMAC......: {}", info.mac);
            println!("\tIP.......: {}", info.ip);
            println!("\tNet Addr.: {}", info.cidr);
            println!("\tLen hosts: {}", info.host_len);
            println!("\tMTU......: {}", info.mtu);
            println!("\tGateway..: {}", info.gateway);
            println!("")
        }
    }

}