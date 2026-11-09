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


pub const SIGNAL: &str = "+";


pub struct Ipv4Iter {
    total: u64,
    current: u32,
    end: u32,
    start_u32: u32,
    end_u32: u32,
}


impl Ipv4Iter {
    pub fn new(cidr: &str, range_str: &str) -> Result<Self, io::Error> {
        let (network_u32, broadcast_u32) = parse_cidr(cidr)?;

        let usable_start = network_u32.saturating_add(1);
        let usable_end = broadcast_u32.saturating_sub(1);
        let cidr_has_usable = usable_start <= usable_end;

        let (start_range, end_range) = if !range_str.is_empty() {
            let s = range_str.trim();
            parse_range(s, usable_start, usable_end, cidr_has_usable)?
        } else if cidr_has_usable {
            (usable_start, usable_end)
        } else {
            (network_u32, network_u32)
        };

        if start_range > end_range {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Start IP cannot be greater than end IP",
            ));
        }

        let total = (end_range - start_range + 1) as u64;

        Ok(Self {
            total,
            current: start_range,
            end: end_range,
            start_u32: start_range,
            end_u32: end_range,
        })
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn start_u32(&self) -> u32 {
        self.start_u32
    }

    pub fn end_u32(&self) -> u32 {
        self.end_u32
    }

    pub fn reset(&mut self) {
        self.current = self.start_u32;
    }
}



impl Iterator for Ipv4Iter {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current > self.end {
            return None;
        }

        let ip = Ipv4Addr::from(self.current);

        if self.current == self.end {
            self.current = self.end.saturating_add(1);
            if self.end == u32::MAX {
                self.current = 1;
                self.end = 0;
            }
        } else {
            self.current += 1;
        }

        Some(ip)
    }
}


fn parse_cidr(cidr: &str) -> Result<(u32, u32), io::Error> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid CIDR: {}", cidr),
        ));
    }

    let ip = parse_ip_address(parts[0])?;
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

    let network = ip_u32 & mask;
    let broadcast = network | !mask;

    Ok((network, broadcast))
}

fn parse_range(
    range_str: &str,
    usable_start: u32,
    usable_end: u32,
    cidr_has_usable: bool,
) -> Result<(u32, u32), io::Error> {
    if range_str.contains(SIGNAL) {
        parse_wildcard_range(range_str, usable_start, usable_end, cidr_has_usable)
    } else {
        parse_single_ip_range(range_str)
    }
}

fn parse_single_ip_range(ip_str: &str) -> Result<(u32, u32), io::Error> {
    let ip = parse_ip_address(ip_str)?;
    let ip_u32 = u32::from(ip);
    Ok((ip_u32, ip_u32))
}

fn parse_wildcard_range(
    range_str: &str,
    usable_start: u32,
    usable_end: u32,
    cidr_has_usable: bool,
) -> Result<(u32, u32), io::Error> {
    let parts: Vec<&str> = range_str.splitn(2, SIGNAL).collect();
    if parts.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid range format: {}", range_str),
        ));
    }

    let start_part = parts[0].trim();
    let end_part = parts[1].trim();

    let start_ip = if !start_part.is_empty() {
        let ip = parse_ip_address(start_part)?;
        Some(u32::from(ip))
    } else {
        None
    };

    let end_ip = if !end_part.is_empty() {
        let ip = parse_ip_address(end_part)?;
        Some(u32::from(ip))
    } else {
        None
    };

    let start_in_cidr = start_ip.map_or(false, |u| {
        cidr_has_usable && u >= usable_start && u <= usable_end
    });

    let end_in_cidr = end_ip.map_or(false, |u| {
        cidr_has_usable && u >= usable_start && u <= usable_end
    });

    match (start_part.is_empty(), end_part.is_empty()) {
        (false, false) => Ok((start_ip.unwrap(), end_ip.unwrap())),

        (false, true) => {
            let start = start_ip.unwrap();
            if !start_in_cidr {
                let ip = Ipv4Addr::from(start);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Start IP {} is outside CIDR range. When using 'IP+', the IP must be within the CIDR", ip),
                ));
            }
            Ok((start, usable_end))
        }

        (true, false) => {
            let end = end_ip.unwrap();
            if !end_in_cidr {
                let ip = Ipv4Addr::from(end);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("End IP {} is outside CIDR range. When using '+IP', the IP must be within the CIDR", ip),
                ));
            }
            Ok((usable_start, end))
        }

        (true, true) => {
            if cidr_has_usable {
                Ok((usable_start, usable_end))
            } else {
                Ok((usable_start, usable_start))
            }
        }
    }
}

fn parse_ip_address(ip_str: &str) -> Result<Ipv4Addr, io::Error> {
    Ipv4Addr::from_str(ip_str).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid IP address '{}': {}", ip_str, e),
        )
    })
}