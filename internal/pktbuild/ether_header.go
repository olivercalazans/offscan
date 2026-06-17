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

package pktbuild

import (
	"encoding/binary"
	"net"
)


type etherHeader struct {
	header  *[14]byte
}



func (eh *etherHeader) SetDstAddr(dstMAC net.HardwareAddr) {
	copy(eh.header[0:6], dstMAC)
}



func (eh *etherHeader) SetSrcAddr(srcMAC net.HardwareAddr) {
	copy(eh.header[6:12], srcMAC)
}



func (eh *etherHeader) setArpType() {
	binary.BigEndian.PutUint16(eh.header[12:14], 0x806)
}