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

 
#[derive(Debug, Default, Clone)]
pub struct Dot11Dissector<'a> {
    pub frame: &'a [u8],
    pub ssid_data: &'a [u8], // IE 0x00
    pub ds_param: &'a [u8],  // IE 0x03 (channel)
    pub rsn: &'a [u8],       // IE 0x30 (WPA2)
    pub ht_cap: &'a [u8],    // IE 0x2D (802.11n)
    pub vht_cap: &'a [u8],   // IE 0xBF (802.11ac)
    pub he_cap: &'a [u8],    // IE 0xFF (802.11ax)
    pub ht_info: &'a [u8],   // IE 0x3D (802.11n)
    pub vht_ops: &'a [u8],   // IE 0xC0 (802.11ac)
    pub wpa1_data: &'a [u8], // IE 0xDD (Vendor Specific - WPA1)
    pub wps_data: &'a [u8],  // IE 0xDD (Vendor Specific - WPS)
    pub timestamp: u64,
    pub is_beacon: bool,
    pub is_data_frm: bool,
}

impl<'a> Dot11Dissector<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update_pkt(&mut self, frame: &'a [u8]) {
        self.frame = frame;
        self.reset();
        self.remove_radiotap();
        self.check_frame_type();
        if self.is_beacon {
            self.cache_ies();
        }
    }

    pub fn reset(&mut self) {
        self.is_beacon = false;
        self.is_data_frm = false;
        self.timestamp = 0;
        self.ssid_data = &[];
        self.ds_param = &[];
        self.rsn = &[];
        self.ht_cap = &[];
        self.vht_cap = &[];
        self.he_cap = &[];
        self.wpa1_data = &[];
        self.wps_data = &[];
        self.ht_info = &[];
        self.vht_ops = &[];
    }

    pub fn remove_radiotap(&mut self) {
        if self.frame.len() < 4 || self.frame[0] != 0x00 {
            return;
        }

        let rt_len = u16::from_le_bytes([self.frame[2], self.frame[3]]) as usize;
        if rt_len > 0 && rt_len < self.frame.len() {
            self.frame = &self.frame[rt_len..];
        }
    }

    pub fn check_frame_type(&mut self) {
        if self.check_if_is_beacon() {
            return;
        }
        if self.check_if_is_data_frame() {
            return;
        }
    }

    pub fn cache_ies(&mut self) {
        let len_frm = self.frame.len();

        if !self.is_beacon || len_frm < 36 {
            return;
        }

        if len_frm >= 32 {
            self.timestamp = u64::from_le_bytes(self.frame[24..32].try_into().unwrap());
        }

        let mut offset = 36;
        while offset + 2 <= len_frm {
            let ie_id = self.frame[offset];
            let ie_len = self.frame[offset + 1] as usize;
            if offset + 2 + ie_len > len_frm {
                break;
            }

            let data = &self.frame[offset + 2..offset + 2 + ie_len];

            match ie_id {
                0x00 => self.ssid_data = data, // SSID
                0x03 => self.ds_param = data,  // Channel
                0x30 => self.rsn = data,       // RSN (WPA2)
                0x2D => self.ht_cap = data,    // 802.11n
                0xBF => self.vht_cap = data,   // 802.11ac
                0xFF => self.he_cap = data,    // 802.11ax
                0x3D => self.ht_info = data,   // 802.11n
                0xC0 => self.vht_ops = data,   // 802.11ac
                0xDD => {
                    // Vendor Specific
                    if data.len() >= 4 {
                        let oui = &data[0..3];
                        if oui == [0x00, 0x50, 0xF2] {
                            match data[3] {
                                0x01 => self.wpa1_data = &data[4..], // WPA1
                                0x04 => self.wps_data = &data[4..],  // WPS
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }

            offset += 2 + ie_len;
        }
    }
}