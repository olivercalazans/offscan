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

const CIPHER_WEP      : u8 = 1;
const CIPHER_TKIP     : u8 = 2;
const CIPHER_CCMP     : u8 = 3;
const CIPHER_WEP104   : u8 = 4;
const CIPHER_GCMP     : u8 = 5;
const CIPHER_GCMP256  : u8 = 6;
const CIPHER_CCMP256  : u8 = 7;


#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecurityCipher(pub u8);


impl SecurityCipher {

    pub fn cipher_str(self) -> &'static str {
        match self.0 {
            CIPHER_WEP     => "WEP",
            CIPHER_TKIP    => "TKIP",
            CIPHER_CCMP    => "CCMP",
            CIPHER_WEP104  => "WEP104",
            CIPHER_GCMP    => "GCMP",
            CIPHER_GCMP256 => "GCMP-256",
            CIPHER_CCMP256 => "CCMP-256",
            _              => "",
        }
    }


    pub fn cipher_len_str(self) -> usize {
        match self.0 {
            CIPHER_WEP     => 3,
            CIPHER_TKIP    => 4,
            CIPHER_CCMP    => 4,
            CIPHER_WEP104  => 6,
            CIPHER_GCMP    => 4,
            CIPHER_GCMP256 => 8,
            CIPHER_CCMP256 => 8,
            _              => 0,
        }
    }

}