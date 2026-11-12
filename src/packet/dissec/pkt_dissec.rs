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




pub struct PacketDissector<'a> {
    pub pkt            : &'a [u8],
    pub is_ipv4        : bool,
    pub is_arp_reply   : bool,
    pub is_arp_request : bool,
    pub is_dhcp        : bool,
}


impl<'a> PacketDissector<'a> {

    pub fn new() -> Self {
        Self {
            pkt: &[],
            is_ipv4: false,
            is_arp_reply: false,
            is_arp_request: false,
            is_dhcp: false,
        }
    }


    #[inline]
    pub fn update_pkt(&mut self, raw_pkt: &'a [u8]) {
        self.pkt = raw_pkt;
        self.reset_flags();
    }


    #[inline]
    fn reset_flags(&mut self) {
        self.is_ipv4 = false;
        self.is_arp_reply = false;
        self.is_arp_request = false;
        self.is_dhcp = false;
    }
}