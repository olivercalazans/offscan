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

const LEN_ICMP_HDR  : usize = 8;
const LEN_ICMP_TOTAL: usize = 20 + LEN_ICMP_HDR;



pub struct IcmpPacket {
    buffer      : [u8; LEN_ICMP_TOTAL],
    ip_header   : IpHeader,
    icmp_header : [u8; LEN_ICMP_HDR],
}


impl IcmpPacket {

    pub fn new() -> Self {
        let mut pkt = Self {
            buffer      : [0u8; LEN_ICMP_TOTAL],
            ip_header   : IpHeader::new(),
            icmp_header : [0u8; LEN_ICMP_HDR],
        };

        pkt.build_fixed();
        pkt
    }


    fn build_fixed(&mut self) {
        self.ip_header.build_fixed();
        self.ip_header.set_proto(1);
        self.ip_header.set_len(LEN_ICMP_HDR as u16);

        self.set_type();
        self.set_code();
        self.set_id();
        self.set_seq_num();
        self.calculate_checksum();
    }


    fn set_type(&mut self) {
        self.icmp_header[0] = 8;
    }


    fn set_code(&mut self) {
        self.icmp_header[1] = 0;
    }


    fn set_id(&mut self) {
        self.icmp_header[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    }


    fn set_seq_num(&mut self) {
        self.icmp_header[6..8].copy_from_slice(&1u16.to_be_bytes());
    }


    fn calculate_checksum(&mut self) {
        self.icmp_header[2..4].copy_from_slice(&[0u8; 2]);
        let ck = self.checksum();
        self.icmp_header[2..4].copy_from_slice(&ck.to_be_bytes());
    }


    fn checksum(&self) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;

        while i + 1 < LEN_ICMP_HDR {
            sum += ((self.icmp_header[i] as u32) << 8) | (self.icmp_header[i + 1] as u32);
            i += 2;
        }

        if i < LEN_ICMP_HDR {
            sum += (self.icmp_header[i] as u32) << 8;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }


    pub fn pkt(&mut self) -> &[u8] {
        self.ip_header.calculate_checksum();
        self.copy_ip_header();
        self.copy_icmp_header();
        &self.buffer
    }


    fn copy_ip_header(&mut self) {
        self.buffer[..20].copy_from_slice(self.ip_header.as_bytes());
    }


    fn copy_icmp_header(&mut self) {
        self.buffer[20..LEN_ICMP_TOTAL].copy_from_slice(&self.icmp_header);
    }

}


impl Default for IcmpPacket {
    fn default() -> Self {
        Self::new()
    }
}