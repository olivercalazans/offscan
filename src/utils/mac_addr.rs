#[derive(Clone)]
pub(crate) struct MacAddr {
    mac: [u8; 6],
}


impl MacAddr {

    pub fn new(vec_u8: [u8; 6]) -> Self {
        Self { mac: vec_u8, }
    }



    pub fn from_str(mac_str: &str) -> Result<Self, String> {
        let parts: Vec<&str> = mac_str.split(':').collect();
        
        if parts.len() != 6 {
            return Err(format!("Invalid MAC: {}", mac_str));
        }

        let mut mac = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            mac[i] = u8::from_str_radix(part, 16)
                .map_err(|_| format!("Invalid part in MAC: '{}'", part))?;
        }

        Ok(Self{ mac, })
    }



    pub fn to_string(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac[0], self.mac[1], self.mac[2],
            self.mac[3], self.mac[4], self.mac[5]
        )
    }
}