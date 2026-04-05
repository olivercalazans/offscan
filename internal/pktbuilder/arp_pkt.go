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

package pktbuilder

import (
	"net"
)


type ArpPkt struct {
	buffer [28]byte
}



func NewArpPkt() *ArpPkt {
	ap := &ArpPkt{}
	ap.buildFixed()
	return ap
}



func (ap *ArpPkt) buildFixed() {
	ap.buffer[0] = 0x00   // HTYPE = 1 (Ethernet) - big endian
	ap.buffer[1] = 0x01
	ap.buffer[2] = 0x08   // PTYPE = 0x0800 (IPv4) - big endian
	ap.buffer[3] = 0x00
	ap.buffer[4] = 0x06   // HLEN = 6
	ap.buffer[5] = 0x04   // PLEN = 4
	ap.buffer[6] = 0x00   // OPER = 1 (request) - big endian
	ap.buffer[7] = 0x01
	// THA (6 bytes, 18:24) - zero 
}



func (ap *ArpPkt) AddStaticAddrs(
	srcMac net.HardwareAddr,
	srcIP  net.IP,
) {
	// 0:8 - fixed
	copy(ap.buffer[8:14], srcMac)
	copy(ap.buffer[14:18], srcIP)
	// 18:24 - fixed
}



func (ap *ArpPkt) L3Pkt(dstIP net.IP) []byte {
	copy(ap.buffer[24:28], dstIP)
	return ap.buffer[:]
}