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

use std::fmt;

const SEC_TYPE_NONE : u8 = 0;
const SEC_TYPE_OPEN : u8 = 1;
const SEC_TYPE_WEP  : u8 = 2;
const SEC_TYPE_WPA  : u8 = 3;


#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecurityType(pub u8);


#[derive(Clone, Copy)]
pub struct WifiSec {
    pub sec_type : SecurityType,
    pub auth     : SecurityAuth,
    pub cipher   : SecurityCipher,
    pub version  : u8,
}


impl WifiSec {

    pub fn is_wpa3(&self) -> bool {
        self.auth == SecurityAuth(AUTH_SAE) || self.auth == SecurityAuth(AUTH_OWE)
    }


    pub fn wpa_str_flag(&self) -> String {
        let mut ver = "WPA";

        if self.version == 2 {
            ver = if self.is_wpa3() { "WPA3" } else { "WPA2" }
        }

        let auth_str   = self.auth.auth_str();
        let cipher_str = self.cipher.cipher_str();

        if auth_str.is_empty() && cipher_str.is_empty() {
            return ver.to_string();
        }

        format!("{}-{}-{}", ver, auth_str, cipher_str)
    }


    pub fn len(&self) -> usize {
        match self.sec_type.0 {
            SEC_TYPE_OPEN => 4,  // "OPEN"
            SEC_TYPE_WEP  => 3,  // "WEP"
            SEC_TYPE_WPA  => self.wpa_str_len(),
            _             => 7,  // "unknown"
        }
    }


    pub fn wpa_str_len(&self) -> usize {
        if self.version == 1 {
            return 3;    // "WPA"
        }

        if self.is_wpa3() {
            return 4;    // "WPA3"
        }

        let mut total = 4;  // "WPA2"

        let auth_len = self.auth.auth_len_str();
        if auth_len > 0 {
            total += 1 + auth_len;
        }

        let cipher_len = self.cipher.cipher_len_str();
        if cipher_len > 0 {
            total += 1 + cipher_len;
        }

        total
    }

}



impl fmt::Display for WifiSec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.sec_type.0 {
            SEC_TYPE_OPEN => f.write_str("OPEN"),
            SEC_TYPE_WEP  => f.write_str("WEP"),
            SEC_TYPE_WPA  => f.write_str(&self.wpa_str_flag()),
            _             => f.write_str("unknown"),
        }
    }
}