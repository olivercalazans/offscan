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


pub fn display_help() {
    const HELP: &str = concat!(
		"\n### INTERFACE MODE\n\n",
	    "    E.g., $ sudo ./offscan ifmode <FLAGS>\n\n",
	    "    -i, --iface : (Required) Interface\n",
	    "        --man   : (Option)   Set interface on maneged mode\n",
	    "        --mon   : (Option)   Set interface on monitor mode\n",
	);
    
    println!("{HELP}")
}