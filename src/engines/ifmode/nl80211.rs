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

use rustix::io;
use super::attr::{genl_hdr, put_string_attr, put_u32_attr};
use super::conn::{resolve_genl_family, NlConn};
use super::consts::*;



pub(super) struct Nl80211 {
    conn   : NlConn,
    fam_id : u16,
    ver    : u8,
}



impl Nl80211 {

    pub(super) fn new() -> io::Result<Self> {
        let fam_id = resolve_genl_family(NL80211_FAMILY_NAME)?;
        let conn = NlConn::new(NETLINK_GENERIC)?;
        Ok(Nl80211 { conn, fam_id, ver: 1 })
    }



    pub(super) fn exec(&mut self, cmd: u8, attrs: &[u8]) -> io::Result<()> {
        let mut payload = genl_hdr(cmd, self.ver);
        payload.extend_from_slice(attrs);
        let seq = self
            .conn
            .send(self.fam_id, NLM_F_REQUEST | NLM_F_ACK, &payload)?;
        self.conn.recv(seq, true)?;
        Ok(())
    }



    pub(super) fn delete_interface(&mut self, ifindex: i32) -> io::Result<()> {
        let attrs = put_u32_attr(Vec::new(), NL80211_ATTR_IFINDEX, ifindex as u32);
        self.exec(NL80211_CMD_DEL_INTERFACE, &attrs)
    }



    pub(super) fn create_interface(&mut self, wiphy: i32, name: &str, iftype: u32) -> io::Result<()> {
        let attrs = Vec::new();
        let attrs = put_u32_attr(attrs, NL80211_ATTR_WIPHY, wiphy as u32);
        let attrs = put_string_attr(attrs, NL80211_ATTR_IFNAME, name);
        let attrs = put_u32_attr(attrs, NL80211_ATTR_IFTYPE, iftype);
        self.exec(NL80211_CMD_NEW_INTERFACE, &attrs)
    }

}