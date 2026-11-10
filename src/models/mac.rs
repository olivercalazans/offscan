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

use std::{fmt, marker::PhantomData};



#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub struct Address<T> {
    bytes : [u8; 6],
    _kind : PhantomData<T>,
}


impl<T> Address<T> {
    
    pub fn new(bytes: [u8; 6]) -> Self {
        Self { bytes, _kind: PhantomData, }
    }



    pub fn from_str(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(format!("Invalid address: {}", s));
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16)
                .map_err(|_| format!("Invalid part '{}'", part))?;
        }

        Ok(Self::new(bytes))
    }
    


    pub fn from_slice(slice: &[u8]) -> Self {
        Self::new(slice.try_into().unwrap())
    }


    
    pub fn bytes(&self) -> &[u8; 6] {
        &self.bytes
    }

}



impl<T> fmt::Display for Address<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!( f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.bytes[0], self.bytes[1], self.bytes[2],
            self.bytes[3], self.bytes[4], self.bytes[5]
        )
    }
}


#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub enum MacAddr {}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub enum BssidAddr {}


pub type MAC   = Address<MacAddr>;
pub type BSSID = Address<BssidAddr>;