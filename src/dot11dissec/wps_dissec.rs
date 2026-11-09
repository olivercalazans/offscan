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

use crate::models::WPSInfo;
use super::Dot11Dissector;

const ATTR_VERSION: u16 = 0x104A;
const ATTR_WPS_STATE: u16 = 0x1044;
const ATTR_AP_SETUP_LOCKED: u16 = 0x1057;
const ATTR_SELECTED_REGISTRAR: u16 = 0x1053;
const ATTR_VENDOR_EXTENSION: u16 = 0x1049;

impl<'a> Dot11Dissector<'a> {
    pub fn get_wps(&self) -> WPSInfo {
        if self.wps_data.is_empty() {
            return WPSInfo::default();
        }

        self.parse_wps()
    }

    fn parse_wps(&self) -> WPSInfo {
        let mut info = WPSInfo::default();

        let len_data = self.wps_data.len();
        let mut pos = 0;

        while pos + 4 <= len_data {
            let t = u16::from_be_bytes([self.wps_data[pos], self.wps_data[pos + 1]]);
            let l = u16::from_be_bytes([self.wps_data[pos + 2], self.wps_data[pos + 3]]) as usize;

            if pos + 4 + l > len_data {
                break;
            }

            let val = &self.wps_data[pos + 4..pos + 4 + l];

            match t {
                ATTR_VERSION => {
                    if l >= 1 && info.version() == 0 {
                        info.set_version(val[0]);
                    }
                }
                ATTR_WPS_STATE => {
                    if l >= 1 {
                        info.set_config(val[0] == 2);
                        info.set_state_presence();
                    }
                }
                ATTR_AP_SETUP_LOCKED => {
                    if l >= 1 {
                        info.set_ap_setup_lock(val[0] != 0);
                    }
                }
                ATTR_SELECTED_REGISTRAR => {
                    if l >= 1 {
                        info.set_registrar(val[0] != 0);
                    }
                }
                ATTR_VENDOR_EXTENSION => {
                    let v = check_vendor_ext(l, val);
                    if v != 0 {
                        info.set_version(v);
                    }
                }
                _ => {}
            }

            pos += 4 + l;
        }

        info
    }
}

fn check_vendor_ext(l: usize, val: &[u8]) -> u8 {
    if l < 3 || &val[..3] != [0x00, 0x37, 0x2A] {
        return 0;
    }

    let mut subpos = 3;
    while subpos + 2 <= l {
        let sub_type = val[subpos];
        let sub_len = val[subpos + 1] as usize;

        if subpos + 2 + sub_len > l {
            return 0;
        }

        if sub_type == 0x00 && sub_len >= 1 {
            return val[subpos + 2];
        }

        subpos += 2 + sub_len;
    }

    0
}