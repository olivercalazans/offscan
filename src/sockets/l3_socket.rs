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
use rustix::net::{
    ipproto, sendto, socket, sockopt, AddressFamily, SendFlags, SocketAddrV4,
    SocketType,
};
use std::ffi::CString;
use std::io;
use std::net::Ipv4Addr;



pub struct Layer3Socket {
    fd: OwnedFd,
}


impl Layer3Socket {

    pub fn new(iface_name: &str) -> Result<Self, io::Error> {
        let fd = socket(AddressFamily::INET, SocketType::RAW, Some(ipproto::RAW))?;

        sockopt::set_ip_hdrincl(&fd, true)?;

        let iface_cstring = CString::new(iface_name)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        sockopt::set_socket_bind_to_device(&fd, Some(&iface_cstring))?;

        Ok(Self { fd })
    }

 
    pub fn send_to(&self, packet: &[u8], dst: Ipv4Addr) -> Result<usize, io::Error> {
        let addr = SocketAddrV4::new(dst, 0);
        let sent_bytes = sendto(&self.fd, packet, SendFlags::empty(), &addr)?;
        Ok(sent_bytes)
    }

}