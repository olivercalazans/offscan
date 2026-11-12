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


use super::{MacAddr, PacketDissector};


impl<'a> PacketDissector<'a> {

    #[inline]
    pub fn get_ether_src_mac(&self) -> Option<MacAddr> {
        if self.pkt.len() < 12 {
            return None;
        }

        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.pkt[6..12]);
        Some(mac)
    }


    #[inline]
    pub(super) fn get_ether_type(&self) -> u16 {
        if self.pkt.len() < 14 {
            return 0;
        }

        ((self.pkt[12] as u16) << 8) | (self.pkt[13] as u16)
    }
    
}