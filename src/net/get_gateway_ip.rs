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
use std::net::Ipv4Addr;
use std::process;


pub fn gateway_ip(iface_name: &str) -> Result<Ipv4Addr, io::Error> {
    let data = fs::read_to_string("/proc/net/route")?;

    for line in data.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();

        if fields.len() < 4 {
            continue;
        }

        if fields[0] != iface_name {
            continue;
        }

        let gate_hex = fields[2];
        if gate_hex == "00000000" {
            continue;
        }

        if let Ok(ip) = hex_to_ip(gate_hex) {
            return Ok(ip);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Gateway not found",
    ))
}


fn hex_to_ip(hex: &str) -> Result<Ipv4Addr, io::Error> {
    if hex.len() != 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid hex length: need 8 characters",
        ));
    }

    let mut bytes = [0u8; 4];
    for i in 0..4 {
        let val = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, e)
        })?;
        bytes[3 - i] = val;
    }

    Ok(Ipv4Addr::from(bytes))
}


pub fn must_gateway_ip(iface_name: &str) -> Ipv4Addr {
    gateway_ip(iface_name).unwrap_or_else(|err| {
        eprintln!("Unable to get Gateway IP. {}", err);
        process::exit(1);
    })
}