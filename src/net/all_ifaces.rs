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

use rustix::net::if_nametoindex;
use std::fs;
use std::io;
use std::process;


#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub index: u32,
    pub name: String,
}


pub fn must_all_ifaces() -> Vec<NetworkInterface> {
    all_ifaces().unwrap_or_else(|err| {
        eprintln!("Unable to get interface list: {}", err);
        process::exit(1);
    })
}


pub fn all_ifaces() -> Result<Vec<NetworkInterface>, io::Error> {
    let mut interfaces = Vec::new();

    for entry in fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();

        if let Ok(index) = if_nametoindex(&name) {
            interfaces.push(NetworkInterface { index, name });
        }
    }

    Ok(interfaces)
}