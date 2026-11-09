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

const STD_B_G : u8 = 1;
const STD_N   : u8 = 2;
const STD_AC  : u8 = 3;
const STD_AX  : u8 = 4;


#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WifiStd(pub u8);


impl WifiStd {

    pub fn std_str(self) -> &'static str {
        match self.0 {
            STD_B_G => "802.11b/g",
            STD_N   => "802.11n",
            STD_AC  => "802.11ac",
            STD_AX  => "802.11ax",
            _       => "unknown",
        }
    }

}



impl fmt::Display for WifiStd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.std_str())
    }
}