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

use crate::models::{
    BSSID, SecurityAuth, SecurityCipher, SecType, SSID, Uptime, WifiSec, WifiStd,
};
use super::Dot11Dissector;

impl<'a> Dot11Dissector<'a> {
    pub(crate) fn check_if_is_beacon(&mut self) -> bool {
        if self.frame.len() < 24 {
            return false;
        }

        let fc = self.frame[0];
        if ((fc >> 2) & 0x03) == 0 && ((fc >> 4) & 0x0F) == 8 {
            self.is_beacon = true;
            return true;
        }

        false
    }

    pub fn get_timestamp(&self) -> Uptime {
        if !self.is_beacon {
            return Uptime::default();
        }

        let mut secs = self.timestamp / 1_000_000;
        let days = (secs / 86400) as u16;
        secs %= 86400;
        let hours = (secs / 3600) as u8;

        if days == 0 && hours == 0 {
            return Uptime { days: 0, hours: 255 };
        }

        Uptime { days, hours }
    }

    pub fn get_bssid(&self) -> BSSID {
        let mut bssid = [0u8; 6];
        if !self.is_beacon || self.frame.len() < 24 {
            return bssid;
        }
        bssid.copy_from_slice(&self.frame[16..22]);
        bssid
    }

    pub fn get_ssid(&self) -> SSID {
        let mut ssid = SSID::default();

        if !self.is_beacon {
            ssid.set_unknown(true);
            return ssid;
        }

        if self.ssid_data.is_empty() {
            ssid.set_hidden(true);
            return ssid;
        }

        ssid.add_ssid(self.ssid_data);
        ssid
    }

    pub fn get_channel(&self) -> u8 {
        if !self.is_beacon {
            return 0;
        }

        if !self.ds_param.is_empty() {
            return self.ds_param[0];
        }

        if !self.ht_info.is_empty() {
            return self.ht_info[0];
        }

        0
    }

    pub fn get_security(&self) -> WifiSec {
        let mut sec = WifiSec::default();

        if !self.is_beacon {
            return sec;
        }

        if self.frame.len() < 36 {
            sec.sec_type = SecType::Open;
            return sec;
        }

        let cap_info = u16::from_le_bytes([self.frame[34], self.frame[35]]);

        if !self.rsn.is_empty() {
            sec = parse_rsn(self.rsn);
            if sec.sec_type != SecType::None {
                return sec;
            }
        }

        if !self.wpa1_data.is_empty() {
            sec = parse_wpa1(self.wpa1_data);
            if sec.sec_type != SecType::None {
                return sec;
            }
        }

        if (cap_info & 0x0010) != 0 {
            sec.sec_type = SecType::WEP;
            return sec;
        }

        sec.sec_type = SecType::Open;
        sec
    }

    pub fn get_standard(&self) -> WifiStd {
        if !self.is_beacon {
            return WifiStd::StdUnknown;
        }

        // 802.11ax (Wi-Fi 6)
        if !self.he_cap.is_empty() {
            return WifiStd::StdAX;
        }

        // 802.11ac (Wi-Fi 5)
        if !self.vht_cap.is_empty() || !self.vht_ops.is_empty() {
            return WifiStd::StdAC;
        }

        // 802.11n (Wi-Fi 4)
        if !self.ht_cap.is_empty() || !self.ht_info.is_empty() {
            return WifiStd::StdN;
        }

        // Fallback para 802.11b/g
        WifiStd::StdB_G
    }
}

fn parse_rsn(data: &[u8]) -> WifiSec {
    let mut sec = WifiSec {
        sec_type: SecType::WPA,
        version: 2,
        ..Default::default()
    };

    let len_data = data.len();
    if len_data < 2 {
        return sec;
    }

    let mut ptr = 2 + 4; // group cipher

    if len_data < ptr + 2 {
        return sec;
    }

    let pairwise_count = u16::from_le_bytes([data[ptr], data[ptr + 1]]) as usize;
    ptr += 2;

    if pairwise_count > 0 && len_data >= ptr + 4 {
        sec.cipher = decode_cipher(&data[ptr..ptr + 4]);
        ptr += pairwise_count * 4;
    }

    if len_data < ptr + 2 {
        return sec;
    }

    let akm_count = u16::from_le_bytes([data[ptr], data[ptr + 1]]) as usize;
    ptr += 2;

    if akm_count > 0 && len_data >= ptr + 4 {
        sec.auth = decode_akm(&data[ptr..ptr + 4]);
    }

    sec
}

fn parse_wpa1(data: &[u8]) -> WifiSec {
    let mut sec = WifiSec {
        sec_type: SecType::WPA,
        version: 1,
        ..Default::default()
    };

    let len_data = data.len();
    if len_data < 4 {
        return sec;
    }

    let version = u16::from_le_bytes([data[0], data[1]]);
    if version != 1 {
        return sec;
    }

    let mut ptr = 2 + 4; // group cipher

    if len_data < ptr + 2 {
        return sec;
    }

    let pairwise_count = u16::from_le_bytes([data[ptr], data[ptr + 1]]) as usize;
    ptr += 2;

    if pairwise_count > 0 && len_data >= ptr + 4 {
        sec.cipher = decode_cipher(&data[ptr..ptr + 4]);
        ptr += pairwise_count * 4;
    }

    if len_data < ptr + 2 {
        return sec;
    }

    let akm_count = u16::from_le_bytes([data[ptr], data[ptr + 1]]) as usize;
    ptr += 2;

    if akm_count > 0 && len_data >= ptr + 4 {
        sec.auth = decode_akm(&data[ptr..ptr + 4]);
    }

    sec
}

fn decode_cipher(suite: &[u8]) -> SecurityCipher {
    if suite.len() < 4 || suite[0] != 0x00 || suite[1] != 0x0F || suite[2] != 0xAC {
        return SecurityCipher::CipherNone;
    }

    match suite[3] {
        1 => SecurityCipher::CipherWEP,
        2 => SecurityCipher::CipherTKIP,
        4 => SecurityCipher::CipherCCMP,
        5 => SecurityCipher::CipherWEP104,
        6 => SecurityCipher::CipherGCMP,
        8 => SecurityCipher::CipherGCMP256,
        9 => SecurityCipher::CipherCCMP256,
        _ => SecurityCipher::CipherNone,
    }
}

fn decode_akm(suite: &[u8]) -> SecurityAuth {
    if suite.len() < 4 || suite[0] != 0x00 || suite[1] != 0x0F || suite[2] != 0xAC {
        return SecurityAuth::AuthNone;
    }
    match suite[3] {
        1 | 3 | 5 | 7 | 11 | 12 | 13 | 14 | 15 | 16 | 17 => SecurityAuth::AuthMGT,
        2 | 4 | 6 => SecurityAuth::AuthPSK,
        8 | 9 => SecurityAuth::AuthSAE,
        10 => SecurityAuth::AuthAPPeer,
        18 | 19 => SecurityAuth::AuthOWE,
        _ => SecurityAuth::AuthNone,
    }
}