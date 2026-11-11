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

use rustix::fd::OwnedFd;
use rustix::io;
use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::sockopt::{set_socket_timeout, Timeout};
use rustix::net::{self, AddressFamily, Protocol, RecvFlags, SendFlags, SocketType};
use std::num::NonZeroU32;
use std::time::Duration;

use super::attr::{align4, genl_hdr, parse_attrs, put_string_attr};
use super::consts::*;



pub(super) struct NlConn {
    pub fd: OwnedFd,
    pub seq: u32,
}


impl NlConn {

    pub fn new(proto: u32) -> io::Result<Self> {
        let protocol = if proto == 0 {
            None
        } else {
            Some(Protocol::from_raw(
                NonZeroU32::new(proto).expect("protocol != 0"),
            ))
        };

        let fd = net::socket(AddressFamily::NETLINK, SocketType::RAW, protocol)?;
        let _ = set_socket_timeout(&fd, Timeout::Recv, Some(Duration::from_secs(5)));
        let addr = SocketAddrNetlink::new(0, 0);
        net::bind(&fd, &addr)?;

        Ok(NlConn { fd, seq: 0 })
    }



    pub fn send(&mut self, msg_type: u16, flags: u16, payload: &[u8]) -> io::Result<u32> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let total_len = 16 + payload.len();
        let mut msg = vec![0u8; total_len];

        msg[0..4].copy_from_slice(&(total_len as u32).to_le_bytes());
        msg[4..6].copy_from_slice(&msg_type.to_le_bytes());
        msg[6..8].copy_from_slice(&flags.to_le_bytes());
        msg[8..12].copy_from_slice(&seq.to_le_bytes());
        msg[16..].copy_from_slice(payload);

        let dst = SocketAddrNetlink::new(0, 0);
        net::sendto(&self.fd, &msg, SendFlags::empty(), &dst)?;
        Ok(seq)
    }



    pub fn recv(&self, seq: u32, skip_genl: bool) -> io::Result<Option<Vec<u8>>> {
        let mut buf = vec![0u8; 8192];

        loop {
            let (_, n, _) = net::recvfrom(&self.fd, &mut buf[..], RecvFlags::empty())?;
            if n == 0 {
                continue;
            }

            let mut offset = 0usize;
            while offset + 16 <= n {
                let msg_len =
                    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
                
                if msg_len < 16 || offset + msg_len > n {
                    break;
                }
                
                let msg_type = u16::from_le_bytes(buf[offset + 4..offset + 6].try_into().unwrap());
                let msg_seq = u32::from_le_bytes(buf[offset + 8..offset + 12].try_into().unwrap());
                let data = &buf[offset + 16..offset + msg_len];

                let aligned = align4(msg_len);
                if offset + aligned > n {
                    break;
                }
                offset += aligned;

                if msg_seq != seq {
                    continue;
                }

                match msg_type {
                    NLMSG_ERROR => {
                        if data.len() < 4 {
                            return Err(io::Errno::INVAL.into());
                        }

                        let code = i32::from_le_bytes(data[0..4].try_into().unwrap());
                        if code == 0 {
                            return Ok(None);
                        }
                        
                        return Err(io::Errno::from_raw_os_error(-code).into());
                    }

                    NLMSG_DONE => return Ok(None),
                    _ => {
                        if skip_genl {
                            if data.len() < 4 {
                                return Err(io::Errno::INVAL.into());
                            }
                        
                            return Ok(Some(data[4..].to_vec()));
                        }
                        
                        return Ok(Some(data.to_vec()));
                    }
                }
            }
        }
    }

}



pub fn resolve_genl_family(name: &str) -> io::Result<u16> {
    let mut c = NlConn::new(NETLINK_GENERIC)?;

    let payload = genl_hdr(CTRL_CMD_GETFAMILY, 1);
    let payload = put_string_attr(payload, CTRL_ATTR_FAMILY_NAME, name);

    let seq = c.send(GENL_ID_CTRL, NLM_F_REQUEST, &payload)?;
    let data = c.recv(seq, true)?;

    let data = match data {
        Some(d) => d,
        None => return Err(io::Errno::NOENT.into()),
    };

    let attrs = parse_attrs(&data);
    match attrs.get(&CTRL_ATTR_FAMILY_ID) {
        Some(id_buf) if id_buf.len() >= 2 => Ok(u16::from_le_bytes([id_buf[0], id_buf[1]])),
        _ => Err(io::Errno::NOENT.into()),
    }
}