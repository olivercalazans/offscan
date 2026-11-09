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


const LEN_IP_HDR: usize = 20;



pub struct IpHeader {
    header: [u8; LEN_IP_HDR],
}


impl IpHeader {

    pub fn new() -> Self {
        Self { header: [0u8; LEN_IP_HDR] }
    }


    pub fn build_fixed(&mut self) {
        self.set_version_and_ihl();
        self.set_dscp_and_ecn();
        self.set_id();
        self.set_flags_and_frag_offset();
        self.set_ttl();
    }


    fn set_version_and_ihl(&mut self) {
        self.header[0] = (4 << 4) | 5;
    }


    fn set_dscp_and_ecn(&mut self) {
        self.header[1] = 0;
    }


    pub fn set_len(&mut self, layer4_len: u16) {
        let total = (LEN_IP_HDR as u16) + layer4_len;
        self.header[2..4].copy_from_slice(&total.to_be_bytes());
    }


    fn set_id(&mut self) {
        self.header[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    }


    fn set_flags_and_frag_offset(&mut self) {
        // Flags + Fragment offset (bit DF = 1, offset 0)
        self.header[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    }


    fn set_ttl(&mut self) {
        self.header[8] = 64;
    }


    pub fn set_proto(&mut self, proto: u8) {
        self.header[9] = proto;
    }


    pub fn calculate_checksum(&mut self) {
        self.header[10..12].copy_from_slice(&[0, 0]);
        let ck = self.checksum();
        self.header[10..12].copy_from_slice(&ck.to_be_bytes());
    }


    fn checksum(&self) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;

        while i + 1 < LEN_IP_HDR {
            sum += ((self.header[i] as u32) << 8) | (self.header[i + 1] as u32);
            i += 2;
        }

        if i < LEN_IP_HDR {
            sum += (self.header[i] as u32) << 8;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }


    pub fn set_src_ip(&mut self, src_ip: Ipv4Addr) {
        self.header[12..16].copy_from_slice(&src_ip.octets());
    }


    pub fn set_dst_ip(&mut self, dst_ip: Ipv4Addr) {
        self.header[16..20].copy_from_slice(&dst_ip.octets());
    }


    pub fn as_bytes(&self) -> &[u8; LEN_IP_HDR] {
        &self.header
    }

}