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

use crate::internal::models::Mac;


const LEN_ETHER_HDR: usize = 14;



pub struct EtherHeader {
    header: [u8; LEN_ETHER_HDR],
}


impl EtherHeader {

    pub fn new() -> Self {
        Self { header: [0u8; LEN_ETHER_HDR] }
    }


    pub fn set_dst_addr(&mut self, dst_mac: &Mac) {
        self.header[0..6].copy_from_slice(&dst_mac.0);
    }


    pub fn set_src_addr(&mut self, src_mac: &Mac) {
        self.header[6..12].copy_from_slice(&src_mac.0);
    }


    pub fn set_arp_type(&mut self) {
        // ARP ethertype = 0x0806
        self.header[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    }


    pub fn as_bytes(&self) -> &[u8; LEN_ETHER_HDR] {
        &self.header
    }
    
}



impl Default for EtherHeader {
    fn default() -> Self {
        Self::new()
    }
}