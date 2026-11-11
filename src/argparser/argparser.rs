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

#[path = "processor.rs"] 
mod processor;

#[path = "slice_mgr.rs"] 
mod slice_mgr;

#[path = "err_display.rs"] 
mod err_display;

use std::io;
use std::net::Ipv4Addr;
use crate::common::abort;
use crate::models::{Iface, MAC};



#[derive(Debug, Clone, Default)]
pub struct Argument<'a> {
    pub short: &'a str,
    pub long: &'a str,
    pub required: bool,
}



#[derive(Debug, Clone, Default)]
pub struct ArgParser {
    args           : Vec<String>,
    duplicated     : Vec<String>,
    missing_flags  : Vec<String>,
    missing_values : Vec<String>,
    errors         : Vec<String>,
}


impl ArgParser {

    pub fn new(args: Vec<String>) -> Self {
        Self {
            args,
            duplicated     : Vec::new(),
            missing_flags  : Vec::new(),
            missing_values : Vec::new(),
            errors         : Vec::new(),
        }
    }

    
    
    pub fn abort_if_has_error(&mut self) {
        let len_err = self.duplicated.len()
            + self.missing_flags.len()
            + self.errors.len()
            + self.missing_values.len()
            + self.args.len();

        if len_err == 0 {
            return;
        }

        self.display_missing_flags();
        self.display_missing_values();
        self.display_duplicated();
        self.display_errors();
        self.display_remaining_args();

        abort("Error while parsing arguments");
    }

    
    
    pub fn bool(&mut self, arg: &Argument) -> bool {
        let (_, ok) = self.verify_if_has_flags(arg);
        self.remove_from_the_list(arg);
        ok
    }

    
    
    pub fn float64(&mut self, arg: &Argument) -> Option<f64> {
        let (has_long, ok) = self.verify_if_has_flags(arg);

        if !ok {
            return None;
        }

        let str_val = self.get_value(arg, has_long)?;

        match str_val.parse::<f64>() {
            Ok(val) => Some(val),
            Err(err) => {
                self.add_error(arg, err);
                None
            }
        }
    }



    pub fn iface(&mut self, arg: &Argument) -> io::Result<Iface> {
        let (has_long, ok) = self.verify_if_has_flags(arg);

        if !ok {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }

        let str_val = self.get_value(arg, has_long);

        Ok(Iface::new(&str_val))
    }



    pub fn int(&mut self, arg: &Argument) -> Option<usize> {
        let (has_long, ok) = self.verify_if_has_flags(arg);

        if !ok {
            return None;
        }

        let str_val = self.get_value(arg, has_long)?;

        match str_val.parse::<usize>() {
            Ok(val) => Some(val),
            Err(err) => {
                self.add_error(arg, err);
                None
            }
        }
    }

    
    
    pub fn ip(&mut self, arg: &Argument) -> Option<Ipv4Addr> {
        let (has_long, ok) = self.verify_if_has_flags(arg);

        if !ok {
            return None;
        }

        let str_val = self.get_value(arg, has_long)?;

        match str_val.parse::<Ipv4Addr>() {
            Ok(ip) => Some(ip),
            Err(err) => {
                self.add_error(arg, err);
                None
            }
        }
    }

    
    
    pub fn mac(&mut self, arg: &Argument) -> Option<MAC> {
        let (has_long, ok) = self.verify_if_has_flags(arg);

        if !ok {
            return None;
        }

        let str_val = self.get_value(arg, has_long)?;

        match parse_mac(&str_val) {
            Ok(mac) => Some(mac),
            Err(err) => {
                self.add_error(arg, err);
                None
            }
        }
    }

    
    
    pub fn string(&mut self, arg: &Argument) -> Option<String> {
        let (has_long, ok) = self.verify_if_has_flags(arg);

        if !ok {
            return None;
        }

        self.get_value(arg, has_long)
    }
}



fn parse_mac(mac_str: &str) -> Result<MAC, String> {
    let parts: Vec<&str> = mac_str.split(':').collect();

    if parts.len() != 6 {
        return Err("invalid MAC address format".to_string());
    }
    
    MAC::from_str(mac_str)
}