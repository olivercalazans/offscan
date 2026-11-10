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

pub mod attr;
pub mod conn;
pub mod consts;
pub mod nl80211;
pub mod rtnetlink;
pub mod switcher;
pub mod sysfs;

pub use consts::*;
pub use nl80211::Nl80211;
pub use switcher::switch_mode;
pub use sysfs::{ifindex_from_name, phy_index, sanity_check};