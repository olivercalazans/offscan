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


use std::time::{SystemTime, UNIX_EPOCH};


const LEN_BEACON: usize = 150;


pub struct Beacon {
    offset     : usize,
    sec_offset : usize,
    buffer     : [u8; LEN_BEACON],
}


impl Beacon {

    pub fn new() -> Self {
        let mut b = Self {
            offset     : 0,
            sec_offset : 0,
            buffer     : [0u8; LEN_BEACON],
        };

        b.build_fixed();
        b
    }


    fn build_fixed(&mut self) {
        minimal_radiotap_header(&mut self.buffer[..12]);
        self.set_frame_ctrl();
        self.set_duration();
        self.set_dst_addr();
        self.set_interval();
    }


    fn set_frame_ctrl(&mut self) {
        self.buffer[12] = 0x80; // Beacon, management
        self.buffer[13] = 0x00;
    }


    fn set_duration(&mut self) {
        self.buffer[14] = 0x00;
        self.buffer[15] = 0x00;
    }


    fn set_dst_addr(&mut self) {
        let broadcast: [u8; 6] = [0xFF; 6];
        self.buffer[16..22].copy_from_slice(&broadcast);
    }


    pub fn set_src_addr(&mut self, mac: [u8; 6]) {
        self.buffer[22..28].copy_from_slice(&mac);
    }


    pub fn set_bssid(&mut self, bssid: [u8; 6]) {
        self.buffer[28..34].copy_from_slice(&bssid);
    }


    pub fn set_seq_ctrl(&mut self, seq: u16) {
        let seq_ctrl: u16 = (seq & 0x0FFF) << 4;
        self.buffer[34..36].copy_from_slice(&seq_ctrl.to_le_bytes());
    }


    fn set_timestamp(&mut self) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);

        self.buffer[36..44].copy_from_slice(&ts.to_le_bytes());
    }


    fn set_interval(&mut self) {
        self.buffer[44..46].copy_from_slice(&100u16.to_le_bytes());
    }


    fn set_cap_info(&mut self, sec_flags: [u8; 2]) {
        self.buffer[46..48].copy_from_slice(&sec_flags);
    }


    fn set_ssid(&mut self, ssid: &[u8]) {
        let ssid_len = ssid.len();
        self.offset = 48;

        self.buffer[self.offset] = 0x00;   // SSID element ID
        self.offset += 1;

        self.buffer[self.offset] = ssid_len as u8;
        self.offset += 1;

        self.buffer[self.offset..self.offset + ssid_len].copy_from_slice(ssid);
        self.offset += ssid_len;
    }


    fn set_rates(&mut self) {
        self.buffer[self.offset] = 0x01;   // Supported Rates element ID
        self.offset += 1;

        self.buffer[self.offset] = 0x08;
        self.offset += 1;

        let rates: [u8; 8] = [
            0x82, 0x84, 0x8B, 0x96,        // 1, 2, 5.5, 11 Mbps
            0x0C, 0x12, 0x18, 0x24,        // 6, 9, 12, 24 Mbps
        ];
        self.buffer[self.offset..self.offset + 8].copy_from_slice(&rates);
        self.offset += 8;
    }


    fn set_chnl(&mut self, chnl: u8) {
        self.buffer[self.offset] = 0x03;   // DS Parameter Set element ID
        self.offset += 1;

        self.buffer[self.offset] = 0x01;
        self.offset += 1;

        self.buffer[self.offset] = chnl;
        self.offset += 1;
    }


    fn set_tim(&mut self) {
        self.buffer[self.offset] = 0x05;   // TIM element ID
        self.offset += 1;

        self.buffer[self.offset] = 0x04;
        self.offset += 1;

        let tim: [u8; 4] = [0x00, 0x01, 0x00, 0x00];
        self.buffer[self.offset..self.offset + 4].copy_from_slice(&tim);
        self.offset += 4;
    }


    pub fn set_sec(&mut self, sec: &str) {
        self.offset = self.sec_offset;

        let (sec_flags, sec_bytes, len_data_sec) = get_sec_data(sec);
        self.set_cap_info(sec_flags);

        if len_data_sec == 0 {
            return;
        }

        self.buffer[self.offset..self.offset + len_data_sec]
            .copy_from_slice(&sec_bytes[..len_data_sec]);
        self.offset += len_data_sec;

        self.set_ext_supp_rates();
    }


    fn set_ext_supp_rates(&mut self) {
        self.buffer[self.offset] = 0x32;   // Extended Supported Rates element ID
        self.offset += 1;

        self.buffer[self.offset] = 0x04;
        self.offset += 1;

        let ext_rates: [u8; 4] = [0x30, 0x48, 0x60, 0x6C];
        self.buffer[self.offset..self.offset + 4].copy_from_slice(&ext_rates);
        self.offset += 4;
    }


    pub fn set_body_info(&mut self, ssid: &[u8], chnl: u8) {
        self.set_ssid(ssid);
        self.set_rates();
        self.set_chnl(chnl);
        self.set_tim();
        self.sec_offset = self.offset;
    }


    pub fn beacon(&mut self) -> &[u8] {
        self.set_timestamp();
        &self.buffer[..self.offset]
    }

}


impl Default for Beacon {
    fn default() -> Self {
        Self::new()
    }
}


// ──────────────────────────────────────────────────────────────────────
fn get_sec_data(sec: &str) -> ([u8; 2], [u8; 30], usize) {
    match sec {
        "open" => {
            ([0x01, 0x04], [0u8; 30], 0)
        }

        "wpa" => {
            let wpa: [u8; 30] = [
                0xDD, 0x16, 0x00, 0x50, 0xF2, 0x01, 0x01, 0x00,
                0x00, 0x50, 0xF2, 0x02, 0x01, 0x00, 0x00, 0x50,
                0xF2, 0x04, 0x01, 0x00, 0x00, 0x50, 0xF2, 0x02,
                0x00, 0x00,
                0, 0, 0, 0,
            ];

            ([0x11, 0x04], wpa, 26)
        }

        "wpa2" => {
            let wpa2: [u8; 30] = [
                0x30, 0x14, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04,
                0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00,
                0x00, 0x0F, 0xAC, 0x02, 0x00, 0x00,
                0, 0, 0, 0, 0, 0, 0, 0,
            ];

            ([0x11, 0x04], wpa2, 22)
        }

        "wpa3" => {
            let wpa3: [u8; 30] = [
                0x30, 0x18, 0x02, 0x00, 0x00, 0x0F, 0xAC, 0x0C,
                0x01, 0x00, 0x00, 0x0F, 0xAC, 0x0C, 0x01, 0x00,
                0x00, 0x0F, 0xAC, 0x06, 0x00, 0x00, 0x00, 0x0F,
                0xAC, 0x08,
                0, 0, 0, 0,
            ];

            ([0x11, 0x04], wpa3, 26)
        }

        _ => {
            abort("Unknown security flag: {}", sec);
        }
    }
}