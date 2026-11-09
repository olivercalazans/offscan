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

use rustix::net::{socket, AddressFamily, SocketType};
use std::io;
use std::net::Ipv4Addr;
use std::process;

const SIOCGIFADDR: u64 = 0x8915;
const SIOCGIFNETMASK: u64 = 0x891b;

#[repr(C)]
struct Ifreq {
    ifr_name: [u8; 16],
    ifr_ifru: [u8; 24],
}

impl Ifreq {
    fn new(name: &str) -> Self {
        let mut ifr = Self {
            ifr_name: [0u8; 16],
            ifr_ifru: [0u8; 24],
        };
        let bytes = name.as_bytes();
        let len = bytes.len().min(15);
        ifr.ifr_name[..len].copy_from_slice(&bytes[..len]);
        ifr
    }
}


pub fn cidr(iface_name: &str) -> Result<String, io::Error> {
    let fd = socket(AddressFamily::INET, SocketType::DGRAM, None)?;

    let mut ifr_addr = Ifreq::new(iface_name);
    let mut ifr_mask = Ifreq::new(iface_name);

    unsafe {
        if rustix::io::ioctl(&fd, SIOCGIFADDR as _, &mut ifr_addr as *mut _ as *mut _).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("No IPv4 address found for interface {}", iface_name),
            ));
        }

        if rustix::io::ioctl(&fd, SIOCGIFNETMASK as _, &mut ifr_mask as *mut _ as *mut _).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("No netmask found for interface {}", iface_name),
            ));
        }
    }

    let ip_bytes: [u8; 4] = ifr_addr.ifr_ifru[4..8].try_into().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "Invalid IP address structure")
    })?;

    let mask_bytes: [u8; 4] = ifr_mask.ifr_ifru[4..8].try_into().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "Invalid Netmask structure")
    })?;

    let ip = Ipv4Addr::from(ip_bytes);
    let mask_u32 = u32::from_be_bytes(mask_bytes);
    let prefix = mask_u32.count_ones();

    Ok(format!("{}/{}", ip, prefix))
}


pub fn must_cidr(iface_name: &str) -> String {
    cidr(iface_name).unwrap_or_else(|err| {
        eprintln!("Failed to get CIDR for interface {}: {}", iface_name, err);
        process::exit(1);
    })
}