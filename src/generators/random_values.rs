/*
 * Copyright (C) 2025 Oliver R. Calazans Jeronimo
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org>.
 */

use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};


const MIN_PORT: u16 = 49152;
const MAX_PORT: u16 = 65535;

pub type MacAddr = [u8; 6];


pub struct RandomValues {
    rng: StdRng,
    first_ip: u32,
    last_ip: u32,
}


impl RandomValues {
    pub fn new() -> Self {
        Self {
            rng: StdRng::from_entropy(),
            first_ip: 0,
            last_ip: 0,
        }
    }


    pub fn random_port(&mut self) -> u16 {
        self.rng.gen_range(MIN_PORT..=MAX_PORT)
    }


    pub fn random_mac(&mut self) -> MacAddr {
        let mut bytes: MacAddr = self.rng.gen();
        bytes[0] = (bytes[0] | 0x02) & 0xFE;
        bytes
    }


    pub fn random_seq(&mut self) -> u16 {
        self.rng.gen_range(1..=4094)
    }


    pub fn random_case_inversion(&mut self, input: &str) -> String {
        if input.is_empty() {
            return String::new();
        }

        let chars: Vec<char> = input.chars().collect();
        let total_chars = chars.len();

        let change_count = self.determine_change_count(total_chars);
        if change_count == 0 {
            return input.to_string();
        }

        let letter_indices: Vec<usize> = chars
            .iter()
            .enumerate()
            .filter_map(|(i, &c)| {
                if matches!(c, 'a'..='z' | 'A'..='Z') {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();

        if letter_indices.is_empty() {
            return input.to_string();
        }

        let selected = if letter_indices.len() <= change_count {
            letter_indices
        } else {
            let mut shuffled = letter_indices;
            shuffled.shuffle(&mut self.rng);
            shuffled.truncate(change_count);
            shuffled
        };

        invert_case_at_indices(&chars, &selected)
    }


    fn determine_change_count(&mut self, total_chars: usize) -> usize {
        match total_chars {
            0 => 0,
            1..=3 => {
                if self.rng.gen_bool(0.5) {
                    1
                } else {
                    0
                }
            }
            4..=7 => self.rng.gen_range(1..=2),
            8..=15 => {
                let mut max = 4;
                let half = total_chars / 2;
                if half < max {
                    max = half;
                }
                self.rng.gen_range(2..=max)
            }
            16..=31 => {
                let sqrt_based = (total_chars as f64).sqrt().ceil() as usize;
                let mut max = sqrt_based;
                let third = total_chars / 3;
                if third < max {
                    max = third;
                }
                self.rng.gen_range(3..=max)
            }
            _ => {
                let log_based = (total_chars as f64).log2().ceil() as usize;
                let percent_based = total_chars / 10;
                let mut max_changes = log_based;

                if percent_based > max_changes {
                    max_changes = percent_based;
                }

                let quarter = total_chars / 4;
                if quarter < max_changes {
                    max_changes = quarter;
                }

                self.rng.gen_range(5..=max_changes)
            }
        }
    }
}


fn invert_case_at_indices(chars: &[char], indices: &[usize]) -> String {
    let mut result = chars.to_vec();

    for &idx in indices {
        let c = chars[idx];
        result[idx] = match c {
            'a'..='z' => c.to_ascii_uppercase(),
            'A'..='Z' => c.to_ascii_lowercase(),
            _ => c,
        };
    }

    result.into_iter().collect()
}