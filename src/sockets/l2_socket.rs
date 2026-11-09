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
    sockopt, sendto, socket, AddressFamily, Protocol, RecvFlags, SendFlags, SocketAddrLinkLayer,
    SocketType,
};
use std::ffi::CString;
use std::io;

const ETH_P_ALL: u16 = 0x0003;



pub struct Layer2Socket {
    fd: OwnedFd,
    addr: SocketAddrLinkLayer,
}


impl Layer2Socket {

    pub fn new(iface_name: &str, ifindex: i32) -> Result<Self, io::Error> {
        let protocol = Protocol::from_raw((ETH_P_ALL.to_be()) as u32);
        let fd       = socket(AddressFamily::PACKET, SocketType::RAW, Some(protocol))?;

        let iface_cstring = CString::new(iface_name)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
 
        sockopt::set_socket_bind_to_device(&fd, Some(&iface_cstring))?;
        sockopt::set_socket_send_buffer_size(&fd, 1024 * 1024)?;

        let addr = SocketAddrLinkLayer::new(
            Protocol::from_raw(ETH_P_ALL.to_be() as u32),
            ifindex as u32,
        );

        Ok(Self { fd, addr })
    }


    pub fn send(&self, frame: &[u8]) -> Result<usize, io::Error> {
        let sent_bytes = sendto(&self.fd, frame, SendFlags::empty(), &self.addr)?;
        Ok(sent_bytes)
    }

}