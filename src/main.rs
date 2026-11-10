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

mod argparser;
mod common;
mod engines;
mod models;

use std::collections::BTreeMap;
use std::env;
use crate::argparser::{CommandHandler, display_all_help};
use crate::engines::*;
use crate::common::abort;



fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        abort("[-] Error: No input found");
    }

    let mut registry: BTreeMap<String, CommandHandler> = BTreeMap::new();

    registry.insert(
        "ifmode".to_string(),
        CommandHandler {
            run: ifmode::run,
            helper: ifmode::display_help,
        },
    );

    display_header();

    let cmd_name = &args[0];

    if cmd_name == "--help" {
        display_all_help(&registry);
        return;
    }

    match registry.get(cmd_name) {
        Some(engine) => {
            (engine.run)(args[1..].to_vec());
        }
        None => {
            display_all_help(&registry);
            let err_msg = format!("[-] Error: No command '{}'", cmd_name);
            abort(&err_msg);
        }
    }
}


fn display_header() {
    println!("\nOffScan - The offensive security and scanning tool for Wi-Fi");
    println!("Repository: https://github.com/olivercalazans/offscan\n");
}