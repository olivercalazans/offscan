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


use crate::internal::models::MAC;


const LEN_DEAUTH_FRAME: usize = 38;



pub struct Deauth {
    buffer: [u8; LEN_DEAUTH_FRAME],
}


impl Deauth {

    pub fn new() -> Self {
        let mut d = Self { buffer: [0u8; LEN_DEAUTH_FRAME] };
        
        d.build_fixed();
        d
    }


    fn build_fixed(&mut self) {
        minimal_radiotap_header(&mut self.buffer[..12]);
        self.set_frame_ctrl();
        self.set_duration();

        // Reason code = 7 (Class 3 frame received from nonassociated STA)
        self.buffer[36] = 0x07;
        self.buffer[37] = 0x00;
    }


    fn set_frame_ctrl(&mut self) {
        self.buffer[12] = 0xC0; // Frame control: deauth, management
        self.buffer[13] = 0x00;
    }


    fn set_duration(&mut self) {
        self.buffer[14] = 0x3a;
        self.buffer[15] = 0x01;
    }


    #[inline]
    pub fn set_dst_addr(&mut self, addr: Mac) {
        self.buffer[16..22].copy_from_slice(&addr);
    }


    #[inline]
    pub fn set_src_addr(&mut self, addr: Mac) {
        self.buffer[22..28].copy_from_slice(&addr);
    }


    #[inline]
    pub fn set_bssid(&mut self, bssid: Mac) {
        self.buffer[28..34].copy_from_slice(&bssid);
    }


    #[inline]
    pub fn set_seq_ctrl(&mut self, seq: u16) {
        let seq_ctrl: u16 = (seq & 0x0FFF) << 4;
        self.buffer[34..36].copy_from_slice(&seq_ctrl.to_le_bytes());
    }


    #[inline]
    pub fn frame(&self) -> &[u8] {
        &self.buffer
    }

}



impl Default for Deauth {
    fn default() -> Self {
        Self::new()
    }
}