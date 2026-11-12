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
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::process;

use super::{all_ifaces, NetworkInterface};


const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCGIFADDR: u64 = 0x8915;
const IFF_UP: u16 = 0x1;


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



pub fn default_interface() -> Result<NetworkInterface, String> {
    let socket_udp = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

    socket_udp
        .connect("8.8.8.8:80")
        .map_err(|e| format!("Failed to connect UDP socket: {}", e))?;

    let local_ip = match socket_udp.local_addr().map(|a| a.ip()) {
        Ok(IpAddr::V4(ip)) => ip,
        _ => return Err("Failed to resolve local IPv4 address".to_string()),
    };

    let interfaces = all_ifaces().map_err(|e| format!("Unable to get interface list: {}", e))?;

    for iface in interfaces {
        if !is_iface_up(&iface.name) {
            continue;
        }

        if let Some(iface_ip) = get_iface_ipv4(&iface.name) {
            if iface_ip == local_ip {
                return Ok(iface);
            }
        }
    }

    Err(format!("No interface found with IP {}", local_ip))
}