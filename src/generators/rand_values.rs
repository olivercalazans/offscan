use std::net::Ipv4Addr;
use rand::{Rng, rngs::ThreadRng, prelude::SliceRandom};
use crate::addrs::{Mac, Bssid};



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
    fn random_vec_u8_6(&mut self) -> [u8; 6] {
        let mut bytes = [0u8; 6];
        for b in bytes.iter_mut() { *b = self.rng.r#gen(); }
        bytes[0] = (bytes[0] | 0x02) & 0xFE;
        bytes
    }



    #[inline]
    pub fn random_mac(&mut self) -> Mac {
        let bytes = self.random_vec_u8_6();
        Mac::new(bytes)
    }



    #[inline]
    pub fn random_bssid(&mut self) -> Bssid {
        let bytes = self.random_vec_u8_6();
        Bssid::new(bytes )
    }



    #[inline]
    pub fn random_seq(&mut self) -> u16 {
        self.rng.gen_range(1..4095)
    }



    pub fn random_case_inversion(&mut self, input: &str) -> String {
        if input.is_empty() {
            return String::new();
        }

        let chars: Vec<char> = input.chars().collect();
        let total_chars      = chars.len();

        let change_count = self.determine_change_count(total_chars);

        if change_count == 0 {
            return input.to_string();
        }

        let letter_indices: Vec<usize> = chars
            .iter()
            .enumerate()
            .filter(|&(_, &c)| c.is_alphabetic())
            .map(|(idx, _)| idx)
            .collect();

        if letter_indices.is_empty() {
            return input.to_string();
        }

        let selected_indices: Vec<usize> = if letter_indices.len() <= change_count {
            letter_indices
        } else {
            letter_indices
                .choose_multiple(&mut self.rng, change_count)
                .cloned()
                .collect()
        };

        Self::invert_case_at_indices(&chars, &selected_indices)
    }



    fn determine_change_count(&mut self, total_chars: usize) -> usize {
        match total_chars {
            0 => 0,
            1..=3 => {
                if self.rng.gen_bool(0.5) { 1 } else { 0 }
            }
            4..=7 => {
                self.rng.gen_range(1..=2)
            }
            8..=15 => {
                self.rng.gen_range(2..=4.min(total_chars / 2))
            }
            16..=31 => {
                let sqrt_based = (total_chars as f64).sqrt().ceil() as usize;
                self.rng.gen_range(3..=sqrt_based.min(total_chars / 3))
            }
            _ => {
                let log_based     = (total_chars as f64).log2().ceil() as usize;
                let percent_based = total_chars / 10;
                let max_changes   = log_based.max(percent_based).min(total_chars / 4);
                self.rng.gen_range(5..=max_changes)
            }
        }
    }



    fn invert_case_at_indices(chars: &[char], indices: &[usize]) -> String {
        let mut result = String::with_capacity(chars.len());

        for (i, &c) in chars.iter().enumerate() {
            if indices.contains(&i) {
                if c.is_lowercase() {
                    result.push_str(&c.to_uppercase().to_string());
                } else if c.is_uppercase() {
                    result.push_str(&c.to_lowercase().to_string());
                } else {
                    result.push(c);
                }
            } else {
                result.push(c);
            }
        }

        result
    }

}
