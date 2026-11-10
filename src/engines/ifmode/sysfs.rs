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
use std::io;
use std::path::Path;



pub fn phy_index(iface: &str) -> io::Result<i32> {
    let path = format!("/sys/class/net/{}/phy80211/index", iface);
    let data = fs::read_to_string(&path)?;
    data.trim()
        .parse::<i32>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}



pub fn ifindex_from_name(iface: &str) -> io::Result<i32> {
    let path = format!("/sys/class/net/{}/ifindex", iface);
    let data = fs::read_to_string(&path)?;
    data.trim()
        .parse::<i32>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}



pub fn sanity_check(iface: &str, expected_index: i32) -> Result<(), String> {
    let actual = ifindex_from_name(iface)
        .map_err(|e| format!("ifindex for {} not found: {}", iface, e))?;
    if actual != expected_index {
        return Err(format!(
            "index mismatch for {}: expected {}, got {}",
            iface, expected_index, actual
        ));
    }
    let phy_path = format!("/sys/class/net/{}/phy80211", iface);
    if !Path::new(&phy_path).exists() {
        return Err(format!(
            "{} is not a WiFi interface (no {}). Refusing to operate.",
            iface, phy_path
        ));
    }
    Ok(())
}