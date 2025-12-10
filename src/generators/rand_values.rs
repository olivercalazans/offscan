use std::net::Ipv4Addr;
use rand::{Rng, rngs::ThreadRng};



pub struct RandomValues {
    rng: ThreadRng,
    first_ip: u32,
    last_ip:  u32,
}



impl RandomValues {

    pub fn new(first_ip: Option<u32>, last_ip: Option<u32>) -> Self {
        Self { 
            rng:      rand::thread_rng(),
            first_ip: first_ip.unwrap_or_else(|| 0),
            last_ip:  last_ip.unwrap_or_else(|| 0),
        }
    }



    #[inline]
    pub fn get_random_port(&mut self) -> u16 {
        self.rng.gen_range(10000..=65535)
    }



    #[inline]
    pub fn get_random_ip(&mut self) -> Ipv4Addr {
        let rand_num     = self.rng.gen_range(self.first_ip..=self.last_ip);
        let ip: Ipv4Addr = rand_num.into();
        ip
    }



    #[inline]
    pub fn get_random_mac(&mut self) -> [u8; 6] {
        let mut bytes = [0u8; 6];
        for b in bytes.iter_mut() { *b = self.rng.r#gen(); }
        bytes[0] = (bytes[0] | 0x02) & 0xFE;
        bytes
    }



    #[inline]
    pub fn random_u16(&mut self) -> u16 {
        self.rng.r#gen()
    }

}
