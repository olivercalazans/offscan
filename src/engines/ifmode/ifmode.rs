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

use std::process;

use super::nl80211::Nl80211;
use super::rtnetlink::set_link_up;
use super::sysfs::{ifindex_from_name, phy_index};


pub run()


pub fn switch_mode(iface: &str, iface_index: i32, iftype: u32, label: &str) {
    let wiphy = match phy_index(iface) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Unable to resolve phy for {}: {}", iface, e);
            process::exit(1);
        }
    };

    let mut dev = match Nl80211::new() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Unable to open nl80211 socket: {}", e);
            process::exit(1);
        }
    };

    if let Err(e) = set_link_up(iface_index, false) {
        eprintln!("Unable to set interface {} down: {}", iface, e);
        process::exit(1);
    }

    if let Err(e) = dev.delete_interface(iface_index) {
        eprintln!("Unable to delete interface {}: {}", iface, e);
        process::exit(1);
    }

    if let Err(e) = dev.create_interface(wiphy, iface, iftype) {
        eprintln!(
            "Unable to create interface {} on {} mode: {}",
            iface, label, e
        );
        process::exit(1);
    }

    match ifindex_from_name(iface) {
        Ok(new_idx) => {
            if let Err(e) = set_link_up(new_idx, true) {
                eprintln!("Unable to set interface {} up: {}", iface, e);
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Unable to resolve new ifindex for {}: {}", iface, e);
            process::exit(1);
        }
    }
}