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

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::Resolver;
use std::net::{IpAddr, Ipv4Addr};


pub fn get_host_name(ip: Ipv4Addr) -> String {
    let resolver = match Resolver::new(ResolverConfig::default(), ResolverOpts::default()) {
        Ok(r) => r,
        Err(_) => return "Unknown".to_string(),
    };

    match resolver.reverse_lookup(IpAddr::V4(ip)) {
        Ok(lookup) => {
            if let Some(name) = lookup.iter().next() {
                name.to_utf8().trim_end_matches('.').to_string()
            } else {
                "Unknown".to_string()
            }
        }
        Err(_) => "Unknown".to_string(),
    }
}