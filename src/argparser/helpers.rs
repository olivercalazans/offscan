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

use std::collections::BTreeMap;
use std::process;
use super::Argument;



pub fn format_arg(arg: &Argument) -> String {
    let mut flags = Vec::new();

    if !arg.short.is_empty() {
        flags.push(arg.short);
    }

    if !arg.long.is_empty() {
        flags.push(arg.long);
    }

    flags.join(", ")
}



pub struct CommandHandler {
    pub run: fn(Vec<String>),
    pub helper: fn(),
}



pub fn display_all_help(registry: &BTreeMap<String, CommandHandler>) {
    for (_cmd, reg) in registry {
        (reg.helper)();
    }

    process::exit(0);
}