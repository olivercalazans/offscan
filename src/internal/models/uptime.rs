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


#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Uptime {
    pub days:  u16, // 2 bytes
    pub hours: u8,  // 1 byte
    // padding: 1 byte
}


impl Uptime {

    pub fn new(days: u16, hours: u8) -> Self {
        Self { days, hours }
    }


    fn is_less_than_hour(&self) -> bool {
        self.hours == 255
    }


    fn is_unknown(&self) -> bool {
        self.days == 0 && self.hours == 0
    }
}



impl fmt::Display for Uptime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_unknown() {
            return f.write_str("unknown");
        }

        if self.is_less_than_hour() {
            return f.write_str("less than 1h");
        }

        if self.days > 0 {
            return write!(f, "{}d {:02}h", self.days, self.hours);
        }

        write!(f, "{}h", self.hours)
    }
}