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

use std::fmt;

#[derive(Debug)]
pub enum CustomErr {
    NotFound(String),
    InvalidLen(String),
    InvalidInput(String),
    NonReq,
    MissFlagOrValue,
    Io(std::io::Error),
    Unknown(String),
}



impl fmt::Display for CustomErr {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(err) => write!(f, "{}", err),
            Self::InvalidLen(err) => write!(f, "{}", err),
            Self::InvalidInput(err) => write!(f, "{}", err),
            Self::NonReq => Ok(()),
            Self::MissFlagOrValue => Ok(()),
            Self::Io(err) => write!(f, "IO error: {}", err),
            Self::Unknown(err) => write!(f, "Unknown error: {}", err)
        }
    }

}


impl std::error::Error for CustomErr {}

impl From<std::io::Error> for CustomErr {
    fn from(err: std::io::Error) -> Self {
        CustomErr::Io(err)
    }
}