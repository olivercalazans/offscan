use std::net::Ipv4Addr;
use rand::{Rng, rngs::ThreadRng};



pub(crate) struct RandomValues {
    rng      : ThreadRng,
    first_ip : u32,
    last_ip  : u32,
}


impl RandomValues {

    pub fn new(first_ip: Option<u32>, last_ip: Option<u32>) -> Self {
        Self { 
            rng      : rand::thread_rng(),
            first_ip : first_ip.unwrap_or_else(|| 0),
            last_ip  : last_ip.unwrap_or_else(|| 0),
        }
    }



    #[inline]
    pub fn random_port(&mut self) -> u16 {
        self.rng.gen_range(49152..=65535)
    }



    #[inline]
    pub fn random_ip(&mut self) -> Ipv4Addr {
        let rand_num     = self.rng.gen_range(self.first_ip..=self.last_ip);
        let ip: Ipv4Addr = rand_num.into();
        ip
    }



    #[inline]
    pub fn random_mac(&mut self) -> [u8; 6] {
        let mut bytes = [0u8; 6];
        for b in bytes.iter_mut() { *b = self.rng.r#gen(); }
        bytes[0] = (bytes[0] | 0x02) & 0xFE;
        bytes
    }



    #[inline]
    pub fn random_seq(&mut self) -> u16 {
        self.rng.gen_range(1..4095)
    }



    pub fn random_char_to_uppercase(&mut self, input: &str) -> String {
        if input.is_empty() {
            return String::new();
        }

        let lowercase_indices: Vec<usize> = input
            .char_indices()
            .filter(|(_, c)| c.is_lowercase())
            .map(|(idx, _)| idx)
            .collect();

        if lowercase_indices.is_empty() {
            return input.to_string();
        }

        let random_idx = self.rng.gen_range(0..lowercase_indices.len());
        let char_start = lowercase_indices[random_idx];

        let char_str: String = input[char_start..].chars().next().unwrap().to_string();
        let char_len = char_str.len();

        let mut result = String::with_capacity(input.len());

        result.push_str(&input[..char_start]);
        result.push_str(&char_str.to_uppercase());
        result.push_str(&input[char_start + char_len..]);

        result
    }

}
