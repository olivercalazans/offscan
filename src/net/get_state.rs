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
use std::process;


pub fn state(iface_name: &str) -> Result<String, io::Error> {
    let path = format!("/sys/class/net/{}/operstate", iface_name);
    let data = fs::read_to_string(path)?;
    Ok(data.trim().to_uppercase())
}


pub fn must_state(iface_name: &str) -> String {
    state(iface_name).unwrap_or_else(|err| {
        eprintln!("Failed to get state for interface {}: {}", iface_name, err);
        process::exit(1);
    })
}