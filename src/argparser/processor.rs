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

use super::{ArgParser, Argument};

impl ArgParser {

    pub(crate) fn get_value(&mut self, arg: &Argument, has_long: bool) -> Option<String> {
        if has_long {
            self.get_flag_value(arg.long)
        } else {
            self.get_flag_value(arg.short)
        }
    }

    
    
    pub(crate) fn verify_if_has_flags(&mut self, arg: &Argument) -> (bool, bool) {
        let has_long = !arg.long.is_empty() && self.args.iter().any(|a| a == arg.long);
        let has_short = !arg.short.is_empty() && self.args.iter().any(|a| a == arg.short);

        if arg.required && !has_long && !has_short {
            self.add_miss_req_flags_warn(arg);
            return (false, false);
        }

        if has_long && has_short {
            self.add_duplicated_warn(arg);
            self.remove_from_the_list(arg);
            return (false, false);
        }

        let mut count = 0;

        if has_long {
            count = self.count(arg.long);
        } else if has_short {
            count = self.count(arg.short);
        }

        if count > 1 {
            self.add_duplicated_warn(arg);
            self.remove_from_the_list(arg);
            return (false, false);
        }

        (has_long, has_long || has_short)
    }

    pub(crate) fn get_flag_value(&mut self, flag: &str) -> Option<String> {
        let index_flag = self.get_flag_index(flag)?;

        let index_value = match self.get_value_index(index_flag) {
            Some(idx) => idx,
            None => {
                self.add_missing_value_warn(flag);
                self.remove_index(index_flag);
                return None;
            }
        };

        let value = self.args[index_value].clone();
        self.remove_flag_and_value(index_flag, index_value);

        Some(value)
    }
}