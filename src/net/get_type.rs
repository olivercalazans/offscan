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

use std::fs;
use super::is_wireless;


pub fn iface_type(iface_name: &str) -> String {
    if is_wireless(iface_name) {
        return "Wireless".to_string();
    }

    let path = format!("/sys/class/net/{}/type", iface_name);
    let Ok(data) = fs::read_to_string(path) else {
        return "Unknown".to_string();
    };

    match data.trim() {
        "1" => "Ethernet".to_string(),
        "772" => "Loopback".to_string(),
        other => format!("Type-{}", other),
    }
}