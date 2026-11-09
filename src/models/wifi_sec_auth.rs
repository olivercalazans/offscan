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


const AUTH_PSK     : u8 = 1;
const AUTH_MGT     : u8 = 2;
const AUTH_SAE     : u8 = 3;
const AUTH_OWE     : u8 = 4;
const AUTH_AP_PEER : u8 = 5;


#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecurityAuth(pub u8);


impl SecurityAuth {

    pub fn auth_str(self) -> &'static str {
        match self.0 {
            AUTH_PSK     => "PSK",
            AUTH_MGT     => "MGT",
            AUTH_SAE     => "SAE",
            AUTH_OWE     => "OWE",
            AUTH_AP_PEER => "AP-PEER",
            _            => "",
        }
    }


    pub fn auth_len_str(self) -> usize {
        match self.0 {
            1 | 2 | 3 | 4 => 3,
            5             => 7,
            _             => 0,
        }
    }

}