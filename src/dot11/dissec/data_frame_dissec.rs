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

use crate::models::MAC;
use super::Dot11Dissector;

impl<'a> Dot11Dissector<'a> {
    pub(crate) fn check_if_is_data_frame(&mut self) -> bool {
        if self.frame.len() < 24 {
            return false;
        }

        let frame_control = self.frame[0];
        let f_type = (frame_control >> 2) & 0x03;

        if f_type != 2 {
            return false;
        }

        self.is_data_frm = true;
        true
    }

    pub fn get_addrs(&self) -> (MAC, MAC, bool) {
        let (to_ds, from_ds) = self.get_ds_flags();

        if (to_ds && from_ds) || (!to_ds && !from_ds) {
            return ([0u8; 6], [0u8; 6], false);
        }

        let addr1 = self.get_addr1();
        let addr2 = self.get_addr2();

        if to_ds {
            let valid = is_valid(&addr2);
            (addr1, addr2, valid)
        } else {
            let valid = is_valid(&addr1);
            (addr2, addr1, valid)
        }
    }

    pub fn get_ds_flags(&self) -> (bool, bool) {
        if self.frame.len() < 2 {
            return (false, false);
        }

        let flags = self.frame[1];
        let to_ds = (flags >> 0) & 0x01;
        let from_ds = (flags >> 1) & 0x01;

        (to_ds == 1, from_ds == 1)
    }

    pub fn get_addr1(&self) -> MAC {
        let mut addr = [0u8; 6];
        if self.frame.len() >= 10 {
            addr.copy_from_slice(&self.frame[4..10]);
        }
        addr
    }

    pub fn get_addr2(&self) -> MAC {
        let mut addr = [0u8; 6];
        if self.frame.len() >= 16 {
            addr.copy_from_slice(&self.frame[10..16]);
        }
        addr
    }
}

pub fn is_valid(mac: &MAC) -> bool {
    // Multicast IPv4
    if mac[0] == 0x01 && mac[1] == 0x00 {
        return false;
    }

    // Multicast IPv6
    if mac[0] == 0x33 && mac[1] == 0x33 {
        return false;
    }

    // Multicast (STP)
    if mac[0] == 0x01 && mac[1] == 0x80 && mac[2] == 0xC2 {
        return false;
    }

    // Broadcast
    if mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF {
        return false;
    }

    true
}