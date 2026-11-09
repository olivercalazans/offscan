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

const PATH: &str = "/proc/sys/net/ipv4/ip_forward";


pub fn enable_ip_forwarding() -> Result<(), io::Error> {
    fs::write(PATH, "1")
}


pub fn disable_ip_forwarding() -> Result<(), io::Error> {
    fs::write(PATH, "0")
}


pub fn must_enable_ip_forwarding() {
    if let Err(err) = enable_ip_forwarding() {
        eprintln!("Unable to enable IP forwarding {}: {}", PATH, err);
        process::exit(1);
    }
}


pub fn must_disable_ip_forwarding() {
    if let Err(err) = disable_ip_forwarding() {
        eprintln!("Unable to disable IP forwarding {}: {}", PATH, err);
        process::exit(1);
    }
}