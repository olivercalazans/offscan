use std::fs;
use crate::iface::IfaceInfo;
use crate::engines::NetInfoArgs;



#[derive(Default)]
pub struct NetworkInfo {
    iface       : String,
    state       : String, 
    if_type     : String, 
    mac         : String, 
    ip          : String, 
    cidr        : String, 
    host_len    : String, 
    mtu         : String, 
    gateway_mac : String, 
    gateway_ip  : String,
    broadcast   : String,
}



impl NetworkInfo {

    pub fn new(_args: NetInfoArgs) -> Self {
        Self { ..Default::default() }
    }



    pub fn execute(&mut self) {
        IfaceInfo::ifaces()
            .into_iter()
            .enumerate()
            .for_each(|(i, iface)|{
                self.set_iface(iface)
                    .set_state()
                    .set_type()
                    .set_mac()
                    .set_ip()
                    .set_cidr()
                    .set_len_host()
                    .set_mtu()
                    .set_gateway_mac()
                    .set_gateway_ip()
                    .set_broadcast()
                    .display_info(i);
            }
        )
    }



    fn set_iface(&mut self, iface: String) -> &mut Self {
        self.iface = iface;
        self
    }



    fn set_state(&mut self) -> &mut Self {
        self.state = IfaceInfo::get_info("operstate", &self.iface).to_uppercase();
        self
    }

    
    
    fn set_type(&mut self) -> &mut Self {        
        if IfaceInfo::is_wireless(&self.iface) {
            self.if_type = "Wireless".to_string();
            return self;
        }
        
        let type_path = format!("/sys/class/net/{}/type", &self.iface);
        
        self.if_type = fs::read_to_string(&type_path)
            .map(|content| {
                match content.trim() {
                    "1"   => "Ethernet".to_string(),
                    "772" => "Loopback".to_string(),
                    _     => format!("Type-{}", content.trim()),
                }
            })
            .unwrap_or_else(|_| "Unknown".to_string());
        
        if self.if_type == "Ethernet" && self.iface == "lo" {
            self.if_type = "Loopback".to_string();
        }
        
        self
    }
    


    fn set_mac(&mut self) -> &mut Self {
        self.mac = IfaceInfo::mac(&self.iface);
        self
    }

    
    
    fn set_ip(&mut self) -> &mut Self {
        self.ip = match IfaceInfo::ip(&self.iface) {
            Ok(ip) => ip.to_string(),
            Err(_) => "None".to_string(),
        };

        self
    }

    
    
    fn set_cidr(&mut self) -> &mut Self {
        self.cidr = match IfaceInfo::cidr(&self.iface) {
            Ok(ip) => ip.to_string(),
            Err(_) => "Unknown".to_string(),
        };

        self
    }

    
    
    fn set_len_host(&mut self) -> &mut Self {
        let parts: Vec<&str> = self.cidr.split('/').collect();
        if parts.len() != 2 {
            self.host_len = "None".to_string();
            return self;
        }

        let cidr_value: u8 = match parts[1].parse() {
            Ok(value) => value,
            Err(_)    => {
                self.host_len = "Unknown".to_string();
                return self;
            }
        };

        if cidr_value > 32 {
            self.host_len = "None".to_string();
            return self;
        }

        let host_bits   = 32 - cidr_value;
        let total_hosts = 2u32.pow(host_bits as u32);

        if cidr_value >= 31 {
            self.host_len = total_hosts.to_string();
            return self;
        }
        
        self.host_len = (total_hosts - 2).to_string();

        self
    }



    fn set_mtu(&mut self) -> &mut Self {
        self.mtu = IfaceInfo::get_info("mtu", &self.iface);
        self
    }



    fn set_gateway_mac(&mut self) -> &mut Self {
        self.gateway_mac = match IfaceInfo::gateway_mac(&self.iface) {
            Ok(mac) => mac,
            Err(_)  => "Unknown".to_string()
        };
        
        self
    }



    fn set_gateway_ip(&mut self) -> &mut Self {
        let content = fs::read_to_string("/proc/net/route")
            .unwrap_or_default();
        
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() < 8 || parts[0] != self.iface {
                continue;
            }

            let gateway_hex = parts[2];
            if gateway_hex == "00000000" {
                continue;
            }

            if let Some(gateway) = Self::hex_to_ip(gateway_hex) {
                self.gateway_ip = gateway;
                return self;
            }
        }

        self.gateway_ip = "Unknown".to_string();
        self
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



    fn set_broadcast(&mut self) -> &mut Self {
        let broadcast  = IfaceInfo::broadcast_ip(&self.iface);
        self.broadcast = broadcast.to_string();
        self
    }

    
    
    fn display_info(&self, index: usize) {
        println!("#{} Interface: {} - State: {}", index, self.iface, self.state);
        println!("  - Type.......: {}", self.if_type);
        println!("  - MAC........: {}", self.mac);
        println!("  - IP.........: {}", self.ip);
        println!("  - Net Addr...: {}", self.cidr);
        println!("  - Len hosts..: {}", self.host_len);
        println!("  - MTU........: {}", self.mtu);
        println!("  - Gateway MAC: {}", self.gateway_mac);
        println!("  - Gateway IP.: {}", self.gateway_ip);
        println!("  - Broadcast..: {}", self.broadcast);
        println!("")
    }

}



impl crate::EngineTrait for NetworkInfo {
    type Args = NetInfoArgs;
    
    fn new(args: Self::Args) -> Self {
        NetworkInfo::new(args)
    }
    
    fn execute(&mut self) {
        self.execute();
    }
}