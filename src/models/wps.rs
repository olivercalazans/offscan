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

const WPS_VERSION_MASK       : u8 = 0x03;
const WPS_CONFIG_MASK        : u8 = 0x08;
const WPS_AP_SETUP_LOCKED    : u8 = 0x10;
const WPS_STATE_PRESENT      : u8 = 0x20;
const WPS_SELECTED_REGISTRAR : u8 = 0x40;


#[derive(Clone, Copy, Debug, Default)]
pub struct WpsInfo {
    bitmask: u8,
}


impl WpsInfo {

    pub fn new() -> Self {
        Self { bitmask: 0 }
    }


    pub fn set_version(&mut self, v: u8) {
        self.bitmask &= !WPS_VERSION_MASK;
        self.bitmask |= (v >> 4) & WPS_VERSION_MASK;
    }


    pub fn version(&self) -> u8 {
        self.bitmask & WPS_VERSION_MASK
    }


    pub fn set_config(&mut self, configured: bool) {
        if configured {
            self.bitmask |= WPS_CONFIG_MASK;
        }
    }


    pub fn is_configured(&self) -> bool {
        (self.bitmask & WPS_CONFIG_MASK) == WPS_CONFIG_MASK
    }


    pub fn set_ap_setup_lock(&mut self, locked: bool) {
        if locked {
            self.bitmask |= WPS_AP_SETUP_LOCKED;
        }
    }


    pub fn is_locked(&self) -> bool {
        (self.bitmask & WPS_AP_SETUP_LOCKED) == WPS_AP_SETUP_LOCKED
    }


    pub fn set_state_presence(&mut self) {
        self.bitmask |= WPS_STATE_PRESENT;
    }


    pub fn is_state_present(&self) -> bool {
        (self.bitmask & WPS_STATE_PRESENT) == WPS_STATE_PRESENT
    }


    pub fn set_registrar(&mut self, selected: bool) {
        if selected {
            self.bitmask |= WPS_SELECTED_REGISTRAR;
        }
    }


    pub fn selected_registrar(&self) -> bool {
        (self.bitmask & WPS_SELECTED_REGISTRAR) == WPS_SELECTED_REGISTRAR
    }


    fn format_version(&self) -> String {
        format!("{}.0", self.version())
    }


    pub fn len(&self) -> usize {
        if self.is_locked() {
            return 6;  // Locked
        }

        let mut total = 3;  // "X.0"

        if self.selected_registrar() {
            total += 4;  // ' ' + RGT
        }

        if self.is_state_present() {
            if self.is_configured() {
                total += 5;  // ' ' + CONF
            } else {
                total += 7;  // ' ' + UNCONF
            }
        }

        total
    }

}



impl fmt::Display for WpsInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.version() == 0 && !self.is_state_present() && !self.is_locked() {
            return f.write_str("0.0");
        }

        if self.is_locked() {
            return f.write_str("Locked");
        }

        f.write_str(&self.format_version())?;

        if self.selected_registrar() {
            f.write_str(" RGT")?;
        }

        if self.is_state_present() {
            if self.is_configured() {
                f.write_str(" CONF")?;
            } else {
                f.write_str(" UNCONF")?;
            }
        }

        Ok(())
    }
}