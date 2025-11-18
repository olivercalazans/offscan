use std::net::Ipv4Addr;
use rand::{Rng, rngs::ThreadRng};



pub struct RandValues {
    rng: ThreadRng,
}



impl RandValues {

    pub fn new() -> Self {
        Self { rng: rand::thread_rng()}
    }



    #[inline]
    pub fn get_random_port(&mut self) -> u16 {
        self.rng.gen_range(10000..=65535)
    }



    #[inline]
    pub fn get_random_ip(&mut self, start: u32, end: u32) -> Ipv4Addr {
        let rand_num     = self.rng.gen_range(start..=end);
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

}
