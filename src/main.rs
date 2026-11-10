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
use std::env;
use std::process;


use argparser::{display_all_help, CommandHandler};
use engines::{
    arppoison, beacon, deauth, fwd, hostdisc, ifmode as engine_ifmode, info, l2disc, pixiedust,
    wifimap,
};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        eprintln!("[-] Error: No input found");
        process::exit(1);
    }

    let mut registry: BTreeMap<String, CommandHandler> = BTreeMap::new();

    registry.insert(
        "arp".to_string(),
        CommandHandler {
            run: arppoison::run,
            helper: arppoison::display_help,
        },
    );
    registry.insert(
        "beacon".to_string(),
        CommandHandler {
            run: beacon::run,
            helper: beacon::display_help,
        },
    );
    registry.insert(
        "deauth".to_string(),
        CommandHandler {
            run: deauth::run,
            helper: deauth::display_help,
        },
    );
    registry.insert(
        "fwd".to_string(),
        CommandHandler {
            run: fwd::run,
            helper: fwd::display_help,
        },
    );
    registry.insert(
        "hdisc".to_string(),
        CommandHandler {
            run: hostdisc::run,
            helper: hostdisc::display_help,
        },
    );
    registry.insert(
        "ifmode".to_string(),
        CommandHandler {
            run: engine_ifmode::run,
            helper: engine_ifmode::display_help,
        },
    );
    registry.insert(
        "info".to_string(),
        CommandHandler {
            run: info::run,
            helper: info::display_help,
        },
    );
    registry.insert(
        "l2disc".to_string(),
        CommandHandler {
            run: l2disc::run,
            helper: l2disc::display_help,
        },
    );
    registry.insert(
        "pixie".to_string(),
        CommandHandler {
            run: pixiedust::run,
            helper: pixiedust::display_help,
        },
    );
    registry.insert(
        "wmap".to_string(),
        CommandHandler {
            run: wifimap::run,
            helper: wifimap::display_help,
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
            eprintln!("[-] Error: No command '{}'", cmd_name);
            process::exit(1);
        }
    }
}


fn display_header() {
    println!("\nOffScan - The offensive security and scanning tool for Wi-Fi");
    println!("Repository: https://github.com/olivercalazans/offscan\n");
}