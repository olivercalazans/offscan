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

#[path = "parser.rs"]
mod parser;

#[path = "getters.rs"]
mod getters;

use std::process;
use crate::argparser::ArgParser;
use crate::common::abort;
use crate::models::Iface;
use super::nl80211::Nl80211;
use super::rtnetlink::set_link_up;



pub fn run(args:Vec<String>) {
    let ifmode = IfaceMode::new(args);
    ifmode.execute();
}



struct IfaceMode {
    iface : Iface,
    mon   : bool,
    man   : bool,
}



impl IfaceMode {

    fn new(args: Vec<String>) -> Self {
        let mut parser = ArgParser::new(args);

        Self {
            iface : 
            mon   : Self::parse_monitor_flag(&mut parser),
            man   : Self::parse_managed_flag(&mut parser),
        }
    }



    fn execute(&self) {
        let phy = self.get_phy();
        let mut dev = self.open_nl80211_socket();

        self.set_iface_down();
        self.delete_iface(&mut dev);
        self.create_iface(&mut dev, phy);
        self.set_iface_up();
    }



    fn open_nl80211_socket(&self) -> Nl80211 {
        let dev = Nl80211::new()
            .unwrap_or_else(|e|
                abort(&format!("Unable to open nl80211 socket: {}", e))
            );

        dev
    }



    fn set_iface_down(&self) {
        let index = self.get_index();

        if let Err(e) = set_link_up(index, false) {
            abort(&format!("Unable to set interface {} down: {}", self.iface.name(), e));
        }
    }



    fn delete_iface(&self, dev: &mut Nl80211) {
        let index = self.get_index();

        if let Err(e) = dev.delete_interface(index) {
            abort(&format!("Unable to delete interface {}: {}", self.iface.name(), e));
        }
    }



    fn create_iface(&self, dev: &mut Nl80211, phy: i32) {
        if let Err(e) = dev.create_interface(phy, self.iface.name(), self.get_mode()) {
            abort(&format!(
                "Unable to create interface {} on {} mode: {}", self.iface.name(), self.get_label(), e)
            );
        }
    }



    fn set_iface_up(&self) {
        let index = self.get_index();

        if let Err(e) = set_link_up(index, true) {
            abort(&format!("Unable to set interface {} up: {}", self.iface.name(), e));
        }
    }

}