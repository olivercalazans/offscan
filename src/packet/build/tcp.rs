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


const LEN_TCP_HDR   : usize = 20;
const LEN_TCP_TOTAL : usize = 20 + LEN_TCP_HDR;


pub struct TcpPacket {
    buffer     : [u8; LEN_TCP_TOTAL],
    ip_header  : IpHeader,
    tcp_header : [u8; LEN_TCP_HDR],
}


impl TcpPacket {

    pub fn new() -> Self {
        let mut pkt = Self {
            buffer     : [0u8; LEN_TCP_TOTAL],
            ip_header  : IpHeader::new(),
            tcp_header : [0u8; LEN_TCP_HDR],
        };
        
        pkt.build_fixed();
        pkt
    }


    fn build_fixed(&mut self) {
        self.ip_header.build_fixed();
        self.ip_header.set_proto(6);
        self.ip_header.set_len(LEN_TCP_HDR as u16);

        self.set_seq_num();
        self.set_ack_num();
        self.set_data_offset();
        self.set_ctrl_flags();
        self.set_window_size();
        self.set_urgent_pointer();
    }


    #[inline]
    pub fn set_src_port(&mut self, src_port: u16) {
        self.tcp_header[0..2].copy_from_slice(&src_port.to_be_bytes());
    }


    #[inline]
    pub fn set_dst_port(&mut self, dst_port: u16) {
        self.tcp_header[2..4].copy_from_slice(&dst_port.to_be_bytes());
    }


    fn set_seq_num(&mut self) {
        self.tcp_header[4..8].copy_from_slice(&1u32.to_be_bytes());
    }


    fn set_ack_num(&mut self) {
        self.tcp_header[8..12].copy_from_slice(&0u32.to_be_bytes());
    }


    fn set_data_offset(&mut self) {
        self.tcp_header[12] = 5 << 4;
    }


    fn set_ctrl_flags(&mut self) {
        self.tcp_header[13] = 0x02; // SYN
    }


    fn set_window_size(&mut self) {
        self.tcp_header[14..16].copy_from_slice(&64240u16.to_be_bytes());
    }


    fn set_urgent_pointer(&mut self) {
        self.tcp_header[18..20].copy_from_slice(&0u16.to_be_bytes());
    }


    #[inline]
    fn calculate_checksum(&mut self) {
        self.tcp_header[16..18].copy_from_slice(&[0u8, 2]);
        let ck = self.checksum();
        self.tcp_header[16..18].copy_from_slice(&ck.to_be_bytes());
    }


    #[inline]
    fn checksum(&self) -> u16 {
        let mut sum: u32 = self.tcp_sum();
        let mut i = 0;

        while i + 1 < LEN_TCP_HDR {
            sum += ((self.tcp_header[i] as u32) << 8) | (self.tcp_header[i + 1] as u32);
            i += 2;
        }

        if i < LEN_TCP_HDR {
            sum += (self.tcp_header[i] as u32) << 8;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }


    #[inline]
    fn tcp_sum(&self) -> u32 {
        let mut sum: u32 = 0;
        let ip = self.ip_header.as_bytes();

        // Source IP (12:16)
        sum += ((ip[12] as u32) << 8) | (ip[13] as u32);
        sum += ((ip[14] as u32) << 8) | (ip[15] as u32);

        // Destination IP (16:20)
        sum += ((ip[16] as u32) << 8) | (ip[17] as u32);
        sum += ((ip[18] as u32) << 8) | (ip[19] as u32);

        sum += 6;                        // protocol = TCP
        sum += LEN_TCP_HDR as u32;       // TCP length

        sum
    }


    #[inline]
    pub fn pkt(&mut self) -> &[u8] {
        self.ip_header.calculate_checksum();
        self.calculate_checksum();

        self.copy_ip_header();
        self.copy_tcp_header();

        &self.buffer
    }


    #[inline]
    fn copy_ip_header(&mut self) {
        self.buffer[..20].copy_from_slice(self.ip_header.as_bytes());
    }


    #[inline]
    fn copy_tcp_header(&mut self) {
        self.buffer[20..LEN_TCP_TOTAL].copy_from_slice(&self.tcp_header);
    }

}



impl Default for TcpPacket {
    fn default() -> Self {
        Self::new()
    }
}