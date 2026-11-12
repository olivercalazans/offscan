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

use std::fmt::Display;
use crate::argparser::{ArgParser, Argument, helpers::format_arg};


impl ArgParser {
    
    pub(super) fn get_flag_index(&self, flag: &str) -> Option<usize> {
        if flag.is_empty() {
            return None;
        }

        self.args.iter().position(|v| v == flag)
    }



    pub(super) fn get_value_index(&self, index_flag: usize) -> Option<usize> {
        let index_value = index_flag + 1;

        if index_value >= self.args.len() {
            return None;
        }

        let value = &self.args[index_value];

        if value.starts_with('-') {
            return None;
        }

        Some(index_value)
    }



    pub fn add_missing_value_warn(&mut self, arg: &str) {
        self.missing_values.push(arg.to_string());
    }



    pub fn add_miss_req_flags_warn(&mut self, arg: &Argument) {
        let line = format_arg(arg);
        self.missing_flags.push(line);
    }



    pub fn add_duplicated_warn(&mut self, arg: &Argument) {
        let line = format_arg(arg);
        self.duplicated.push(line);
    }



    pub fn add_error<E: Display>(&mut self, arg: &Argument, err: E) {
        let flags = format_arg(arg);
        let line = format!("{}: {}", flags, err);
        self.errors.push(line);
    }



    pub(super) fn remove_from_the_list(&mut self, arg: &Argument) {
        for _ in 0..self.count(arg.long) {
            if let Some(index) = self.get_flag_index(arg.long) {
                self.remove(index);
            }
        }

        for _ in 0..self.count(arg.short) {
            if let Some(index) = self.get_flag_index(arg.short) {
                self.remove(index);
            }
        }
    }



    pub(super) fn remove(&mut self, index: usize) {
        if let Some(i) = self.get_value_index(index) {
            self.remove_flag_and_value(index, i);
        } else {
            self.remove_index(index);
        }
    }



    pub(super) fn remove_index(&mut self, index_flag: usize) {
        if index_flag < self.args.len() {
            self.args.remove(index_flag);
        }
    }



    pub(super) fn remove_flag_and_value(&mut self, index_flag: usize, index_value: usize) {
        if index_flag < self.args.len() && index_value < self.args.len() {
            self.args.drain(index_flag..=index_value);
        }
    }


    
    pub(super) fn count(&self, flag: &str) -> usize {
        if flag.is_empty() {
            return 0;
        }
        self.args.iter().filter(|&v| v == flag).count()
    }

}