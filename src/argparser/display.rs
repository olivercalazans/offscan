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


use super::ArgParser;


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



impl ArgParser {

    pub(crate) fn display_errors(&self) {
        if self.errors.is_empty() {
            return;
        }

        println!("[!] ERROR(S):");
        for e in &self.errors {
            println!("  {}", e);
        }
        println!();
    }


    pub(crate) fn display_missing_flags(&self) {
        if self.missing_flags.is_empty() {
            return;
        }

        println!("[!] MISSING FLAG(S):");
        for e in &self.missing_flags {
            println!("  {}", e);
        }
        println!();
    }

    
    pub(crate) fn display_missing_values(&self) {
        if self.missing_values.is_empty() {
            return;
        }

        println!("[!] MISSING VALUE(S) FOR FLAG(S):");
        for e in &self.missing_values {
            println!("  {}", e);
        }
        println!();
    }

    
    pub(crate) fn display_duplicated(&self) {
        if self.duplicated.is_empty() {
            return;
        }

        println!("[!] DUPLICATED FLAGS:");
        for e in &self.duplicated {
            println!("  {}", e);
        }
        println!();
    }

    
    pub(crate) fn display_remaining_args(&self) {
        if self.args.is_empty() {
            return;
        }

        println!("[!] Unknown Flag(s):");
        println!("  {}", self.args.join(", "));
        println!();
    }
}