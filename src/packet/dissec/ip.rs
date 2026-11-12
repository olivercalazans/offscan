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

use std::net::Ipv4Addr;
use super::PacketDissector;

impl<'a> PacketDissector<'a> {

    #[inline]
    pub fn is_ipv4(&mut self) -> bool {
        self.is_ipv4 = self.pkt.len() >= 34 && self.get_ether_type() == 0x0800;
        self.is_ipv4
    }


    #[inline]
    pub fn get_src_ip(&self) -> Option<Ipv4Addr> {
        if self.pkt.len() < 30 || !self.is_ipv4 {
            return None;
        }

        let mut ip = [0u8; 4];
        ip.copy_from_slice(&self.pkt[26..30]);
        Some(Ipv4Addr::from(ip))
    }
    
}