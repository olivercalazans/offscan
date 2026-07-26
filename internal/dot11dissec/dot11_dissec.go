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

package dot11dissec

import "encoding/binary"



type Dot11Dissector struct {
	frame       []byte
	dot11Start  int
	IsBeacon    bool
	IsDataFrm   bool
}



func NewDot11Dissector() *Dot11Dissector {
	return &Dot11Dissector{}
}



func (dd *Dot11Dissector) UpdatePkt(frame []byte) {
	dd.frame      = frame
	dd.dot11Start = 0
	dd.IsBeacon   = false
	dd.IsDataFrm  = false

	dd.removeRadiotap()
	dd.checkFrameType()
}



func (dd *Dot11Dissector) removeRadiotap() {
	if len(dd.frame) < 4 || dd.frame[0] != 0x00 { return }

    rtLen := int(binary.LittleEndian.Uint16(dd.frame[2:4]))

    if rtLen > 0 && rtLen < len(dd.frame) {
        dd.frame = dd.frame[rtLen:]
    }
}



func (dd *Dot11Dissector) checkFrameType() {
	if dd.checkIfIsBeacon() { return }
	if dd.checkIfIsDataFrame() { return }
}