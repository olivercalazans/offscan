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
use super::{MacAddr, PacketDissector};

impl<'a> PacketDissector<'a> {
    pub fn is_arp_reply(&self) -> bool {
        self.is_arp_reply
    }

    pub fn is_arp_request(&self) -> bool {
        self.is_arp_request
    }

    pub fn is_arp(&mut self) -> bool {
        if self.pkt.len() < 42 {
            return false;
        }

        if self.get_ether_type() != 0x0806 {
            return false;
        }

        self.check_arp_opcode();
        true
    }

    fn check_arp_opcode(&mut self) {
        let op_code = ((self.pkt[20] as u16) << 8) | (self.pkt[21] as u16);

        self.is_arp_request = op_code == 1;
        self.is_arp_reply = op_code == 2;
    }

    pub fn get_arp_src_ip(&self) -> Option<Ipv4Addr> {
        if self.pkt.len() < 32 {
            return None;
        }

        let mut ip = [0u8; 4];
        ip.copy_from_slice(&self.pkt[28..32]);
        Some(Ipv4Addr::from(ip))
    }

    pub fn get_arp_src_mac(&self) -> Option<MacAddr> {
        if self.pkt.len() < 28 {
            return None;
        }

        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.pkt[22..28]);
        Some(mac)
    }
}