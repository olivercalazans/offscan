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

use std::io;
use std::process;


pub fn validate_channel(channel: u16) -> Result<(), io::Error> {
    if !(1..=165).contains(&channel) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("The channel must be between 1 and 165 (input: {})", channel),
        ));
    }
    Ok(())
}


pub fn must_validate_channel(channel: u16) {
    if let Err(err) = validate_channel(channel) {
        eprintln!("{}", err);
        process::exit(1);
    }
}