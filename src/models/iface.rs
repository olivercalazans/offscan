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
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process;

pub type MacAddr = [u8; 6];

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



pub struct Iface {
    iface: String,
}


impl Iface {

    pub fn new(iface_name: &str) -> Self {
        Self {
            iface: iface_name.to_string(),
        }
    }

    

    pub fn gateway_ip(&self) -> Result<Ipv4Addr, io::Error> {
        let data = fs::read_to_string("/proc/net/route")?;

        for line in data.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();

            if fields.len() < 4 {
                continue;
            }

            if fields[0] != self.iface {
                continue;
            }

            let gate_hex = fields[2];
            if gate_hex == "00000000" {
                continue;
            }

            if let Ok(ip) = Self::hex_to_ip(gate_hex) {
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



    pub fn gateway_mac(&self) -> Result<MacAddr, io::Error> {
        let data = fs::read_to_string("/proc/net/arp")?;

        for line in data.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();

            if fields.len() < 6 {
                continue;
            }

            if fields[5] != self.iface {
                continue;
            }

            let mac_str = fields[3];
            if mac_str == "00:00:00:00:00:00" {
                continue;
            }

            if let Ok(mac) = Self::parse_mac(mac_str) {
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



    pub fn ipv4(&self) -> Result<Ipv4Addr, io::Error> {
        let fd = socket(AddressFamily::INET, SocketType::DGRAM, None)?;
        let mut ifr = Ifreq::new(&self.iface);

        unsafe {
            if rustix::io::ioctl(&fd, SIOCGIFADDR as _, &mut ifr as *mut _ as *mut _).is_err() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no IPv4 address found on interface {}", self.iface),
                ));
            }
        }

        let ip_bytes: [u8; 4] = ifr.ifr_ifru[4..8].try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid IP address structure")
        })?;

        Ok(Ipv4Addr::from(ip_bytes))
    }



    pub fn cidr(&self) -> Result<String, io::Error> {
        let fd = socket(AddressFamily::INET, SocketType::DGRAM, None)?;

        let mut ifr_addr = Ifreq::new(&self.iface);
        let mut ifr_mask = Ifreq::new(&self.iface);

        unsafe {
            if rustix::io::ioctl(&fd, SIOCGIFADDR as _, &mut ifr_addr as *mut _ as *mut _).is_err() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("No IPv4 address found for interface {}", self.iface),
                ));
            }

            if rustix::io::ioctl(&fd, SIOCGIFNETMASK as _, &mut ifr_mask as *mut _ as *mut _).is_err() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("No netmask found for interface {}", self.iface),
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



    pub fn if_type(&self) -> String {
        if self.is_wireless() {
            return "Wireless".to_string();
        }

        let path = format!("/sys/class/net/{}/type", &self.iface);
        let Ok(data) = fs::read_to_string(path) else {
            return "Unknown".to_string();
        };

        match data.trim() {
            "1" => "Ethernet".to_string(),
            "772" => "Loopback".to_string(),
            other => format!("Type-{}", other),
        }
    }



    pub fn is_wireless(&self) -> bool {
        let path = format!("/sys/class/net/{}/wireless", &self.iface);
        Path::new(&path).exists()
    }



    pub fn state(&self) -> Result<String, io::Error> {
        let path = format!("/sys/class/net/{}/operstate", &self.iface);
        let data = fs::read_to_string(path)?;
        Ok(data.trim().to_uppercase())
    }

}