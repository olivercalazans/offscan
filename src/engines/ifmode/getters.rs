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

use crate::common::abort;
use super::IfaceMode;



const NL80211_IFTYPE_MANAGED: u32 = 2;
const NL80211_IFTYPE_MONITOR: u32 = 6;



impl IfaceMode {

    pub(super) fn get_phy(&self) -> i32 {
        let phy = self.iface.phy_index()
            .unwrap_or_else(|e| 
                abort(&format!("Unable to resolve phy for {}: {}", self.iface.name(), e))
            );
        
        phy
    }



    pub(super) fn get_index(&self) -> i32 {
        self.iface.index()
            .unwrap_or_else(|e|
                abort(&format!("Unable to get interface {} index: {}", self.iface.name(), e))
            )
    }



    pub(super) fn get_mode(&self) -> u32 {
        if self.mon {
            return NL80211_IFTYPE_MONITOR;
        }

        NL80211_IFTYPE_MANAGED
    }



    pub(super) fn get_label(&self) -> &str {
        if self.mon {
            return "monitor";
        }

        "managed"
    }

}