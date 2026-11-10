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


use rustix::io;

use super::conn::NlConn;
use super::consts::*;



pub fn set_link_up(ifindex: i32, up: bool) -> io::Result<()> {
    let mut c = NlConn::new(NETLINK_ROUTE)?;

    let mut ifinfo = vec![0u8; 16];
    ifinfo[0] = 0; // AF_UNSPEC
    ifinfo[4..8].copy_from_slice(&(ifindex as u32).to_le_bytes());

    let flags: u32 = if up { IFF_UP } else { 0 };
    ifinfo[8..12].copy_from_slice(&flags.to_le_bytes());
    ifinfo[12..16].copy_from_slice(&IFF_UP.to_le_bytes());

    let seq = c.send(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, &ifinfo)?;
    c.recv(seq, false)?;
    Ok(())
}