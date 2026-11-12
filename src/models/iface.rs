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

use std::{fs, io};
use std::net::Ipv4Addr;
use std::path::Path;
use rustix::ioctl::{ioctl, Updater};
use rustix::net::{socket, AddressFamily, SocketType};
use crate::common::CustomErr;
use crate::models::MAC;
use crate::sys::ensure_iface_exists;



const SIOCGIFADDR    : u64 = 0x8915;
const SIOCGIFNETMASK : u64 = 0x891b;



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

    pub fn new(iface: &str) -> Result<Iface, CustomErr> {
        ensure_iface_exists(iface)?;
        Ok(Self { iface: iface.to_string() })
    }



    pub fn name(&self) -> &str {
        &self.iface
    }



    pub fn phy_index(&self) -> io::Result<i32> {
        let path = format!("/sys/class/net/{}/phy80211/index", &self.iface);
        let data = fs::read_to_string(&path)?;

        data.trim()
            .parse::<i32>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }



    pub fn index(&self) -> io::Result<i32> {
        let path = format!("/sys/class/net/{}/ifindex", &self.iface);
        let data = fs::read_to_string(&path)?;

        data.trim()
            .parse::<i32>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
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



    pub fn ipv4(&self) -> Result<Ipv4Addr, io::Error> {
        let fd = socket(AddressFamily::INET, SocketType::DGRAM, None)?;
        let mut ifr = Ifreq::new(&self.iface);

        unsafe {
            let req = Updater::<{ SIOCGIFADDR as u32 }, _>::new(&mut ifr);
            ioctl(&fd, req).map_err(|_| io::Error::from(io::ErrorKind::NotFound))?;
        }

        Ok(Ipv4Addr::new(
            ifr.ifr_ifru[4],
            ifr.ifr_ifru[5],
            ifr.ifr_ifru[6],
            ifr.ifr_ifru[7],
        ))
    }



    pub fn cidr(&self) -> Result<String, io::Error> {
        let fd = socket(AddressFamily::INET, SocketType::DGRAM, None)?;

        let mut ifr_addr = Ifreq::new(&self.iface);
        let mut ifr_mask = Ifreq::new(&self.iface);

        unsafe {
            let req_addr = Updater::<{ SIOCGIFADDR as u32 }, _>::new(&mut ifr_addr);
            ioctl(&fd, req_addr).map_err(|_| io::Error::from(io::ErrorKind::NotFound))?;

            let req_mask = Updater::<{ SIOCGIFNETMASK as u32 }, _>::new(&mut ifr_mask);
            ioctl(&fd, req_mask).map_err(|_| io::Error::from(io::ErrorKind::NotFound))?;
        }

        let ip = Ipv4Addr::new(
            ifr_addr.ifr_ifru[4],
            ifr_addr.ifr_ifru[5],
            ifr_addr.ifr_ifru[6],
            ifr_addr.ifr_ifru[7],
        );

        let mask_u32 = u32::from_be_bytes([
            ifr_mask.ifr_ifru[4],
            ifr_mask.ifr_ifru[5],
            ifr_mask.ifr_ifru[6],
            ifr_mask.ifr_ifru[7],
        ]);
        let prefix = mask_u32.count_ones();

        Ok(format!("{ip}/{prefix}"))
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
            let val = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidInput, e)
            })?;

            bytes[3 - i] = val;
        }

        Ok(Ipv4Addr::from(bytes))
    }



    pub fn gateway_mac(&self) -> Result<MAC, io::Error> {
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

            if let Ok(mac) = MAC::from_str(mac_str) {
                return Ok(mac);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Gateway MAC not found",
        ))
    }

}