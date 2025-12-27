use std::collections::BTreeSet;
use rand::seq::SliceRandom;
use crate::utils::abort;



pub struct PortIter {
    ports : Vec<u16>,
    index : usize,
}


impl PortIter {

    pub fn new(ports_str: Option<String>, random: bool) -> Self {
        let ports_set = match ports_str {
            Some(s) => Self::get_specific_ports(&s),
            None    => Self::get_default_ports(),
        };
        
        let mut ports: Vec<u16> = ports_set.into_iter().collect();
        if random {
            let mut rng = rand::thread_rng();
            ports.shuffle(&mut rng);
        }

        Self { ports, index: 0 }
    }



    fn get_default_ports() -> BTreeSet<u16> {[
           20,   21,    22,    23,    25,     53,    67,    68,    69,    80,
          110,  139,   143,   161,   179,    194,   443,   445,   465,   514, 
          531,  543,   550,   587,   631,    636,   993,   995,  1080,  1433, 
         1434, 1500,  1521,  1723,  1883,   2049,  2181,  3306,  3372,  3389, 
         3690, 4500,  5000,  5001,  5432,   5800,  5900,  6379,  7070,  7777, 
         7778, 8000,  8080,  8443,  8888,  10000, 11211, 20000, 27017, 50000,
        52000,
    ].into()}



    fn get_specific_ports(ports_str: &str) -> BTreeSet<u16> {
        let mut ports_set = BTreeSet::new();

        for part in ports_str.split(',') {
            if part.contains('-') {
                ports_set.extend(Self::get_port_range(part));
            } else {
                ports_set.insert(Self::validate_port(part));
            }
        }

        ports_set
    }



    fn get_port_range(port_range: &str) -> Vec<u16> {
        let parts: Vec<&str> = port_range.split('-').collect();

        if parts.len() != 2 {
            abort(&format!("Invalid port range format: {}", port_range));
        }

        let start = Self::validate_port(parts[0]);
        let end   = Self::validate_port(parts[1]);

        if start >= end {
            abort(&format!("Invalid range: {}-{}", start, end));
        }

        (start..=end).collect()
    }



    fn validate_port(port_str: &str) -> u16 {
        let port = port_str.parse::<u16>().unwrap_or_else(|_| {
            abort(&format!("Invalid port '{}'. Must be between 1 and 65535", port_str));
        });
        
        if port == 0 {
            abort("Port 0 is reserved and cannot be used");
        }
        
        port
    }



    pub fn len(&self) -> usize {
        self.ports.len()
    }

}



impl Iterator for PortIter {

    type Item = u16;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.ports.len() {
            let port = self.ports[self.index];
            self.index += 1;
            Some(port)
        } else {
            None
        }
    }

}
