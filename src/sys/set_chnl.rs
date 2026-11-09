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

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;


const SIOCSIWFREQ: libc::c_ulong = 0x8B04;

#[repr(C)]
#[derive(Clone, Copy)]
struct IwFreq {
    m: i32,
    e: i16,
    i: u8,
    flags: u8,
}


#[repr(C)]
struct IwReq {
    ifr_name: [u8; 16],
    ifr_data: [u8; 16],
}


struct SocketGuard {
    fd: RawFd,
}


impl Drop for SocketGuard {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}


pub fn try_set_channel(iface_name: &str, channel: i32) -> io::Result<()> {

    if channel <= 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid channel"));
    }

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let _guard = SocketGuard { fd };

    let mut wrq = IwReq {
        ifr_name: [0; 16],
        ifr_data: [0; 16],
    };

    let name_bytes = iface_name.as_bytes();
    if name_bytes.len() >= 16 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Interface name too long"));
    }
    
    wrq.ifr_name[..name_bytes.len()].copy_from_slice(name_bytes);

    let freq = IwFreq {
        m: channel,
        e: 0,
        i: 0,
        flags: 0,
    };

    unsafe {
        std::ptr::copy_nonoverlapping(
            &freq as *const IwFreq as *const u8,
            wrq.ifr_data.as_mut_ptr(),
            std::mem::size_of::<IwFreq>(),
        );
    }

    let res = unsafe {
        libc::ioctl(fd, SIOCSIWFREQ, &mut wrq as *mut IwReq)
    };

    if res < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}


pub fn must_set_channel(iface_name: &str, channel: i32) {
    if let Err(err) = try_set_channel(iface_name, channel) {
        eprintln!("Unable to set channel {} on interface {}: {}", channel, iface_name, err);
        std::process::exit(1);
    }
}