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

use std::io;
use std::net::Ipv4Addr;
use std::str::FromStr;


pub fn broadcast_from_cidr(cidr: &str) -> Result<Ipv4Addr, io::Error> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid CIDR: {}", cidr),
        ));
    }

    let ip = Ipv4Addr::from_str(parts[0]).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid CIDR: {}", e),
        )
    })?;

    let prefix: u32 = parts[1].parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid prefix in CIDR '{}'", cidr),
        )
    })?;

    if prefix > 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid prefix in CIDR '{}'", cidr),
        ));
    }

    let ip_u32 = u32::from(ip);
    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };

    let broadcast_u32 = ip_u32 | !mask;
    Ok(Ipv4Addr::from(broadcast_u32))
}