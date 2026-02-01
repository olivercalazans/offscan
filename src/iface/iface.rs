use std::{ net::Ipv4Addr, ffi::CStr, fs , path::Path, str::FromStr, fmt};
use libc::{ freeifaddrs, AF_INET, sockaddr_in };
use crate::iface::SysInfo;
use crate::utils::{abort, Mac};



#[derive(Clone, Default)]
pub struct Iface{
    iface: String,
}


impl Iface {

    pub fn new(iface_name: &str) -> Self {
        let iface = SysInfo::exists(iface_name)
            .unwrap_or_else(|e| abort(e));

        Self { iface }
    }



    pub fn index(&self) -> i32 {
        let ifindex_path = format!("/sys/class/net/{}/ifindex", &self.iface);
        
        match fs::read_to_string(&ifindex_path) {
            Ok(content) => {
                content.trim().parse().unwrap_or_else(|_| {
                    abort(&format!("Failed to parse ifindex for interface: {}", &self.iface));
                })
            }
            Err(_) => {
                abort(&format!("Uneable to read {}", ifindex_path));
            }
        }
    }



    pub fn name(&self) -> &str {
        &self.iface
    }



    pub fn mac(&self) -> Result<Mac, String> {
        let mac = SysInfo::get_info(&self.iface, "address")?;
        Mac::from_str(&mac)
    }



    pub fn state(&self) -> Result<String, String> {
        let state = SysInfo::get_info(&self.iface, "operstate")?;
        Ok(state.to_uppercase())
    }



    pub fn if_type(&self) -> String {        
        if self.is_wireless() {
            return "Wireless".to_string();
        }
        
        let type_path = format!("/sys/class/net/{}/type", &self.iface);
        
        let mut iface_type = fs::read_to_string(&type_path)
            .map(|content| {
                match content.trim() {
                    "1"   => "Ethernet".to_string(),
                    "772" => "Loopback".to_string(),
                    _     => format!("Type-{}", content.trim()),
                }
            })
            .unwrap_or_else(|_| "Not found".to_string());
        
        if iface_type == "Ethernet" && &self.iface == "lo" {
            iface_type = "Loopback".to_string();
        }
        
        iface_type
    }



    pub fn is_wireless(&self) -> bool {
        Path::new(
            &format!("/sys/class/net/{}/wireless", &self.iface)
        ).exists()
    }



    pub fn ip(&self) -> Result<Ipv4Addr, String> {
        unsafe {
            let ifap    = SysInfo::ifaddrs_ptr();
            let mut cur = ifap;

            while !cur.is_null() {
                let ifa       = &*cur;
                let name_cstr = CStr::from_ptr(ifa.ifa_name);
                let name      = name_cstr.to_string_lossy();

                if name != self.iface
                   || ifa.ifa_addr.is_null()
                   || (*ifa.ifa_addr).sa_family as i32 != AF_INET 
                {
                    cur = ifa.ifa_next;
                    continue;
                }

                let addr = &*(ifa.ifa_addr as *const sockaddr_in);
                let ip   = Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
                freeifaddrs(ifap);

                return Ok(ip);
            }

            freeifaddrs(ifap);
            Err(format!("Interface {} not found or has no IPv4 address", &self.iface))
        }
    }



    pub fn cidr(&self) -> Result<String, String> {
        unsafe {
            let ifap    = SysInfo::ifaddrs_ptr();
            let mut cur = ifap;

            while !cur.is_null() {
                let ifa       = &*cur;
                let name_cstr = CStr::from_ptr(ifa.ifa_name);
                let name      = name_cstr.to_string_lossy();

                if name != self.iface
                    || ifa.ifa_addr.is_null()
                    || ifa.ifa_netmask.is_null()
                    || (*ifa.ifa_addr).sa_family as i32 != AF_INET
                {
                    cur = ifa.ifa_next;
                    continue;
                }

                let addr = &*(ifa.ifa_addr as *const sockaddr_in);
                let ip   = Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());

                let netmask = &*(ifa.ifa_netmask as *const sockaddr_in);
                let mask    = Ipv4Addr::from(netmask.sin_addr.s_addr.to_ne_bytes());

                freeifaddrs(ifap);

                let cidr        = mask.octets().iter().map(|b| b.count_ones()).sum::<u32>() as u8;
                let ip_u32      = u32::from(ip);
                let mask_u32    = u32::from(mask);
                let network_u32 = ip_u32 & mask_u32;
                let network     = Ipv4Addr::from(network_u32.to_be_bytes());

                return Ok(format!("{}/{}", network, cidr));
            }

            freeifaddrs(ifap);
            Err(format!("Interface {} not found or missing IPv4/netmask", &self.iface))
        }
    }



    pub fn gateway_ip(&self) -> Result<Ipv4Addr, String> {
        let content = fs::read_to_string("/proc/net/route")
            .map_err(|e| format!("Uneable to read /proc/net/route: {}", e))?;
        
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() < 8 || parts[0] != &self.iface {
                continue;
            }

            let gateway_hex = parts[2];
            if gateway_hex == "00000000" {
                continue;
            }

            if let Some(gateway) = Self::hex_to_ip(gateway_hex) {
                return Ok(gateway);
            }
        }

        Err("Gateway IP not found".to_string())
    }



    fn hex_to_ip(hex: &str) -> Option<Ipv4Addr> {
        if hex.len() != 8 {
            return None;
        }

        let bytes: Vec<u8> = (0..4)
            .map(|i| u8::from_str_radix(&hex[i*2..i*2+2], 16).ok())
            .collect::<Option<Vec<_>>>()?;

        Some(Ipv4Addr::new(bytes[3], bytes[2], bytes[1], bytes[0]))
    }



    pub fn gateway_mac(&self) -> Result<Mac, String> {
        let arp_content = fs::read_to_string("/proc/net/arp")
            .map_err(|e| format!("Uneable to read /proc/net/arp: {}", e))?;

        for line in arp_content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();

            if fields.len() < 6 || fields[5] != &self.iface {
                continue;
            }

            let mac = fields[3];
            if mac.is_empty() || mac == "00:00:00:00:00:00" {
                continue
            }
            
            return Mac::from_str(mac);
        }

        Err(format!("No MAC address found on interface {}", &self.iface))
    }



    pub fn mtu(&self) -> Result<String, String> {
        SysInfo::get_info(&self.iface, "mtu")
    }



    pub fn broadcast_ip(&self) -> Result<Ipv4Addr, String> {
        let (ip, prefix) = self.ipaddr_and_u8()?;
        let ip_u32       = u32::from(ip);
        
        let mask = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
        let broadcast_u32 = ip_u32 | !mask;
        
        Ok(Ipv4Addr::from(broadcast_u32))
    }

    
    
    fn ipaddr_and_u8(&self) -> Result<(Ipv4Addr, u8), String> {
        let cidr             = self.cidr()?;
        let parts: Vec<&str> = cidr.split('/').collect();
        let ip: Ipv4Addr     = parts[0].parse().unwrap();
        let prefix: u8       = parts[1].parse().unwrap();
        Ok((ip, prefix))
    }

}



impl FromStr for Iface {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err("Interface name cannot be empty".to_string());
        }
        Ok(Iface { iface: s.to_string() })
    }
}


impl fmt::Display for Iface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

 
impl fmt::Debug for Iface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Iface{{iface: {}}}", self.name())
    }
}