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


use super::IfaceMode;
use crate::argparser::{ArgParser, Argument};


impl IfaceMode {

    pub(super) fn parse_iface_flag(parser: &mut ArgParser) -> Iface {
        let arg = Argument{
            short: "-i", long: "--iface", required: true,
        };

        let ok = parser.iface(&arg);
    }


    
    pub(super) fn parse_monitor_flag(parser: &mut ArgParser) -> bool {
        let arg = Argument{
            short: "", long: "--mon", required: false,
        };

        parser.bool(&arg)
    }



    pub(super) fn parse_managed_flag(parser: &mut ArgParser) -> bool {
        let arg = Argument{
            short: "", long: "--man", required: false,
        };

        parser.bool(&arg)
    }

}