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

pub type MacAddr = [u8; 6];


pub fn gateway_mac(iface_name: &str) -> Result<MacAddr, io::Error> {
    let data = fs::read_to_string("/proc/net/arp")?;

    for line in data.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();

        if fields.len() < 6 {
            continue;
        }

        if fields[5] != iface_name {
            continue;
        }

        let mac_str = fields[3];
        if mac_str == "00:00:00:00:00:00" {
            continue;
        }

        if let Ok(mac) = parse_mac(mac_str) {
            return Ok(mac);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Gateway MAC not found",
    ))
}


fn parse_mac(mac_str: &str) -> Result<MacAddr, io::Error> {
    let parts: Vec<&str> = mac_str.split(':').collect();

    if parts.len() != 6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid MAC address format",
        ));
    }

    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(part, 16).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, e)
        })?;
    }

    Ok(bytes)
}


pub fn must_gateway_mac(iface_name: &str) -> MacAddr {
    gateway_mac(iface_name).unwrap_or_else(|err| {
        eprintln!("Unable to get gateway MAC. {}", err);
        process::exit(1);
    })
}