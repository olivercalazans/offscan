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

package dot11build

import (
	"encoding/binary"
	"net"
)


type Deauth struct {
	buffer [38]byte
}



func NewDeauthFrame() Deauth {
	d := Deauth{}
	d.buildFixed()
	return d
}



func (d *Deauth) buildFixed() {
	minimalRariotapHeader(d.buffer[:12])
    d.setFrameCtrl()
    d.setDuration()

    d.buffer[36] = 0x07
    d.buffer[37] = 0x00
}



func (d *Deauth) setFrameCtrl() {
    d.buffer[12] = 0xC0
    d.buffer[13] = 0x00
}



func (d *Deauth) setDuration() {
    d.buffer[14] = 0x3a
    d.buffer[15] = 0x01
}



func (d *Deauth) SetDstAddr(addr net.HardwareAddr) {
    copy(d.buffer[16:22], addr)
}



func (d *Deauth) SetSrcAddr(addr net.HardwareAddr) {
    copy(d.buffer[22:28], addr)
}



func (d *Deauth) SetBSSID(bssid net.HardwareAddr) {
    copy(d.buffer[28:34], bssid)
}



func (d *Deauth) SetSeqCtrl(seq uint16) {
    seqCtrl := (seq & 0x0FFF) << 4
    binary.LittleEndian.PutUint16(d.buffer[34:36], seqCtrl)
}



func (d *Deauth) Frame() [] byte {
    return d.buffer[:]
}