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

const LEN_ARP_HDR   : usize = 28;
const LEN_ARP_TOTAL : usize = 14 + LEN_ARP_HDR;



pub struct ArpPacket {
    buffer       : [u8; LEN_ARP_TOTAL],
    ether_header : EtherHeader,
    arp_header   : [u8; LEN_ARP_HDR],
}


impl ArpPacket {

    pub fn new() -> Self {
        let mut pkt = Self {
            buffer       : [0u8; LEN_ARP_TOTAL],
            ether_header : EtherHeader::new(),
            arp_header   : [0u8; LEN_ARP_HDR],
        };

        pkt.build_fixed();
        pkt
    }


    fn build_fixed(&mut self) {
        self.ether_header.set_arp_type();
        self.set_hardware_type();
        self.set_protocol_type();
        self.set_hardware_addr_len();
        self.set_protocol_addr_len();
    }


    fn set_hardware_type(&mut self) {
        self.arp_header[0..2].copy_from_slice(&0x0001u16.to_be_bytes()); // HTYPE = Ethernet
    }


    fn set_protocol_type(&mut self) {
        self.arp_header[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // PTYPE = IPv4
    }


    fn set_hardware_addr_len(&mut self) {
        self.arp_header[4] = 0x06;
    }


    fn set_protocol_addr_len(&mut self) {
        self.arp_header[5] = 0x04;
    }


    pub fn set_request_opcode(&mut self) {
        self.arp_header[6..8].copy_from_slice(&0x0001u16.to_be_bytes());
    }


    pub fn set_reply_opcode(&mut self) {
        self.arp_header[6..8].copy_from_slice(&0x0002u16.to_be_bytes());
    }


    pub fn set_sender_mac(&mut self, mac: [u8; 6]) {
        self.arp_header[8..14].copy_from_slice(&mac);
    }


    pub fn set_sender_ip(&mut self, ip: Ipv4Addr) {
        self.arp_header[14..18].copy_from_slice(&ip.octets());
    }


    pub fn set_target_mac(&mut self, mac: [u8; 6]) {
        self.arp_header[18..24].copy_from_slice(&mac);
    }


    pub fn set_target_ip(&mut self, ip: Ipv4Addr) {
        self.arp_header[24..28].copy_from_slice(&ip.octets());
    }


    pub fn pkt(&mut self) -> &[u8] {
        self.copy_ether_header();
        self.copy_arp_header();
        &self.buffer
    }


    fn copy_ether_header(&mut self) {
        self.buffer[..14].copy_from_slice(self.ether_header.as_bytes());
    }


    fn copy_arp_header(&mut self) {
        self.buffer[14..LEN_ARP_TOTAL].copy_from_slice(&self.arp_header);
    }

}



impl Default for ArpPacket {
    fn default() -> Self {
        Self::new()
    }
}