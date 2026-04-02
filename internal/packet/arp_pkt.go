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

package packet

import (
	"encoding/binary"
	"net"
)


type ArpPkt struct {
	buffer [42]byte
}



func NewArpPkt() *ArpPkt {
	ap := &ArpPkt{}
	ap.buildFixed()
	return ap
}



func (ap *ArpPkt) buildFixed() {
	// Ethernet header (0 - 14)
	binary.BigEndian.PutUint16(ap.buffer[12:14], 0x0800)

	// ARP header (14 - 42)	
	ap.buffer[14] = 0x00   // HTYPE = 1 (Ethernet) - big endian
	ap.buffer[15] = 0x01
	ap.buffer[16] = 0x08   // PTYPE = 0x0800 (IPv4) - big endian
	ap.buffer[17] = 0x00
	ap.buffer[18] = 0x06   // HLEN = 6
	ap.buffer[19] = 0x04   // PLEN = 4
	ap.buffer[20] = 0x00   // OPER = 1 (request) - big endian
	ap.buffer[21] = 0x01
	// THA (6 bytes, 32:38) - zero 

}



func (ap *ArpPkt) etherHeader(
	srcMac net.HardwareAddr,
	dstMac net.HardwareAddr,
) {
	copy(ap.buffer[0:6], dstMac[:])
    copy(ap.buffer[6:12], srcMac[:])
	// 12:14 - fixed
}



func (ap *ArpPkt) arpHeader(
	srcMac net.HardwareAddr,
	srcIP  net.IP,
) {
	// 14:22 - fixed
	copy(ap.buffer[22:28], srcMac)
	copy(ap.buffer[28:32], srcIP)
	// 32:38 - fixed
}



func (ap *ArpPkt) AddStaticAddrs(
	srcMac net.HardwareAddr,
	dstMac net.HardwareAddr,
	srcIP  net.IP,
) {
	ap.etherHeader(srcMac, dstMac)
	ap.arpHeader(srcMac, srcIP)
}



func (ap *ArpPkt) UpdateDstIp(dstIP net.IP) {
	copy(ap.buffer[38:42], dstIP)
}