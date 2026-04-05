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

package frame80211

import (
	"encoding/binary"
	"net"
)

type Mac = net.HardwareAddr



type Deauth struct {
	buffer [38]byte
}



func NewDeauthFrame(bssid Mac) *Deauth {
	deauth := Deauth{}
	buildFixed(deauth.buffer[:], bssid)
	
	return &deauth
}



func buildFixed(buffer []byte, bssid Mac) {        
	MinimalRariotapHeader(buffer[:12])

    buffer[12] = 0xC0
    buffer[13] = 0x00
    buffer[14] = 0x3a
    buffer[15] = 0x01

    copy(buffer[28:34], bssid)

    buffer[36] = 0x07
    buffer[37] = 0x00
}



func (d *Deauth) Frame(srcMac, dstMac Mac, seq uint16) [] byte {
    copy(d.buffer[16:22], dstMac)
    copy(d.buffer[22:28], srcMac)

    seqCtrl := uint16((seq & 0x0FFF) << 4)
    binary.LittleEndian.PutUint16(d.buffer[34:36], seqCtrl)
    
    return d.buffer[:]
}