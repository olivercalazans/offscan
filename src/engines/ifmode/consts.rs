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

pub const NL80211_FAMILY_NAME: &str = "nl80211";

pub const NL80211_CMD_NEW_INTERFACE: u8 = 7;
pub const NL80211_CMD_DEL_INTERFACE: u8 = 8;

pub const NL80211_ATTR_WIPHY: u16 = 1;
pub const NL80211_ATTR_IFINDEX: u16 = 3;
pub const NL80211_ATTR_IFNAME: u16 = 4;
pub const NL80211_ATTR_IFTYPE: u16 = 5;

pub const RTM_NEWLINK: u16 = 16;
pub const IFF_UP: u32 = 0x1;

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_ACK: u16 = 0x04;

pub const GENL_ID_CTRL: u16 = 0x10;
pub const CTRL_CMD_GETFAMILY: u8 = 3;
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;

pub const NETLINK_ROUTE: u32 = 0;
pub const NETLINK_GENERIC: u32 = 16;

pub const NLMSG_ERROR: u16 = 0x2;
pub const NLMSG_DONE: u16 = 0x3;