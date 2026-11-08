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

use std::fmt;

const SSID_LEN_MASK    : u8 = 0x3F; // 0011 1111
const SSID_HIDDEN_MASK : u8 = 0x40; // 0100 0000
const SSID_UNKNOWN_MASK: u8 = 0x80; // 1000 0000



pub struct Ssid {
    data    : [u8; 32],
    bitmask : u8,
}


impl Ssid {

    pub fn new() -> Self {
        Self { data: [0u8; 32], bitmask: 0 }
    }


    pub fn add_ssid(&mut self, bytes: &[u8]) -> bool {
        let length = bytes.len();

        if length > 32 || length < 1 {
            return false;
        }

        self.set_len(length);
        self.data[..length].copy_from_slice(bytes);

        true
    }


    fn set_len(&mut self, length: usize) {
        self.bitmask = (self.bitmask & !SSID_LEN_MASK) | (length as u8 & SSID_LEN_MASK);
    }


    pub fn len(&self) -> usize {
        (self.bitmask & SSID_LEN_MASK) as usize
    }


    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }


    pub fn is_hidden(&self) -> bool {
        (self.bitmask & SSID_HIDDEN_MASK) != 0
    }


    pub fn is_unknown(&self) -> bool {
        (self.bitmask & SSID_UNKNOWN_MASK) != 0
    }


    pub fn set_hidden(&mut self, hidden: bool) {
        if hidden {
            self.bitmask |= SSID_HIDDEN_MASK;
        } else {
            self.bitmask &= !SSID_HIDDEN_MASK;
        }
    }


    pub fn set_unknown(&mut self, unknown: bool) {
        if unknown {
            self.bitmask |= SSID_UNKNOWN_MASK;
        } else {
            self.bitmask &= !SSID_UNKNOWN_MASK;
        }
    }

    
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len()]
    }

}



impl fmt::Display for Ssid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_unknown() {
            return f.write_str("unknown");
        }
        
        if self.is_hidden() {
            return f.write_str("<hidden>");
        }

        let length = self.len();
        if length == 0 {
            return f.write_str("<empty>");
        }

        f.write_str(&String::from_utf8_lossy(&self.data[..length]))
    }
}



impl Default for Ssid {
    fn default() -> Self {
        Self::new()
    }
}