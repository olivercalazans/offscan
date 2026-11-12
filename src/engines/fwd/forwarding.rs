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

use core::ffi::CStr;
use rustix::fs::{openat, Mode, OFlags, CWD};
use rustix::io::{read, write};
use crate::argparser::{ArgParser, Argument};
use crate::common::abort;


const IPV4_FORWARD_PATH: &CStr = c"/proc/sys/net/ipv4/ip_forward";
const IPV4_FORWARD_PATH_STR: &str = "/proc/sys/net/ipv4/ip_forward";



pub fn run(args: Vec<String>) {
    let mut fwd = Forwarding::default();
    fwd.parse_args(args);
    fwd.execute();
}



#[derive(Default)]
struct Forwarding {
    enable  : bool,
    disable : bool,
}


impl Forwarding {

    fn parse_args(&mut self, args: Vec<String>) {
        let mut parser = ArgParser::new(args);

        let enable_arg = Argument {
            long: "--enable",
            short: "-e",
            required: false,
        };
        self.enable = parser.bool(&enable_arg);

        let disable_arg = Argument {
            long: "--disable",
            short: "-d",
            required: false,
        };
        self.disable = parser.bool(&disable_arg);

        parser.abort_if_has_error();
    }



    fn execute(&self) {
        self.validate_fwd_flags();

        if self.enable {
            enable_ipv4_forwarding();
        }
        
        if self.disable {
            disable_ipv4_forwarding();
        }
    }



    fn validate_fwd_flags(&self) {
        if self.enable && self.disable {
            abort::abort(
                "Both enable and disable flags are provided, but only one can be used at a time",
            );
        }

        if !self.enable && !self.disable {
            abort::abort(
                "No action flag provided. It's necessary to use -e/--enable or -d/--disable",
            );
        }
    }


}



fn is_ipv4_forwarding_enabled() -> bool {
    let fd = match openat(CWD, IPV4_FORWARD_PATH, OFlags::RDONLY, Mode::empty()) {
        Ok(fd) => fd,
        Err(err) => abort::abort(&format!("Failed to read {IPV4_FORWARD_PATH_STR}: {err}")),
    };

    let mut buf = [0u8; 8];
    let n = match read(&fd, &mut buf) {
        Ok(n) => n,
        Err(err) => abort::abort(&format!("Failed to read {IPV4_FORWARD_PATH_STR}: {err}")),
    };

    buf[..n].trim_ascii().first() == Some(&b'1')
}



fn set_ipv4_forwarding(value: &[u8; 1], error_prefix: &str) {
    let fd = match openat(CWD, IPV4_FORWARD_PATH, OFlags::WRONLY, Mode::empty()) {
        Ok(fd) => fd,
        Err(err) => abort::abort(&format!("{error_prefix}: {err}")),
    };

    if let Err(err) = write(&fd, value) {
        abort::abort(&format!("{error_prefix}: {err}"));
    }
}



fn enable_ipv4_forwarding() {
    if is_ipv4_forwarding_enabled() {
        println!("[i] Forwarding already enabled");
        return;
    }

    set_ipv4_forwarding(b"1", "Failed to enable IP forwarding");
}



fn disable_ipv4_forwarding() {
    if !is_ipv4_forwarding_enabled() {
        println!("[i] Forwarding already disabled");
        return;
    }

    set_ipv4_forwarding(b"0", "Failed to disable IP forwarding");
}