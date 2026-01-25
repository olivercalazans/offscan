use crate::iface::{Iface, SysInfo};
use crate::engines::NetInfoArgs;



#[derive(Default)]
pub struct NetworkInfo {
    iface       : Iface,
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
        SysInfo::ifaces()
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
        self.iface = Iface::new(&iface);
        self
    }



    fn set_state(&mut self) -> &mut Self {
        self.state = self.iface.state().unwrap_or_else(|_| "Unknown".to_string());
        self
    }

    
    
    fn set_type(&mut self) -> &mut Self {        
        self.if_type = self.iface.if_type();
        self
    }
    


    fn set_mac(&mut self) -> &mut Self {
        self.mac = match self.iface.mac() {
            Ok(mac) => mac.to_string(),
            Err(_)  => "Unknown".to_string(),
        };

        self
    }

    
    
    fn set_ip(&mut self) -> &mut Self {
        self.ip = match self.iface.ip() {
            Ok(ip) => ip.to_string(),
            Err(_) => "None".to_string(),
        };

        self
    }

    
    
    fn set_cidr(&mut self) -> &mut Self {
        self.cidr = match self.iface.cidr() {
            Ok(cidr) => cidr,
            Err(_)   => "Unknown".to_string(),
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
        self.mtu = self.iface.mtu().unwrap_or_else(|_| "None".to_string());
        self
    }



    fn set_gateway_mac(&mut self) -> &mut Self {
        self.gateway_mac = match self.iface.gateway_mac() {
            Ok(mac) => mac.to_string(),
            Err(_)  => "Unknown".to_string()
        };
        
        self
    }



    fn set_gateway_ip(&mut self) -> &mut Self {
        self.gateway_ip = match self.iface.gateway_ip() {
            Ok(ip) => ip.to_string(),
            Err(_) => "Unknown".to_string()
        };
        
        self
    }



    fn set_broadcast(&mut self) -> &mut Self {
        if &self.if_type == "Loopback" {
            self.broadcast = "None".to_string();
            return self
        }
        
        self.broadcast = match self.iface.broadcast_ip() {
            Ok(ip) => ip.to_string(),
            Err(_) => "Unknown".to_string(),
        };

        self
    }

    
    
    fn display_info(&self, index: usize) {
        println!("#{} Interface: {} - State: {}", index, self.iface.name(), self.state);
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