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

package builder

import (
	"net"
	"offscan/internal/conv"
)


type ArpPacket struct {
	buffer    [42]byte
	arpHdr    [28]byte
	etherHdr  etherHeader
}



func NewArpPkt() ArpPacket {
	ap := ArpPacket{ etherHdr: newEtherHeader() }
	ap.buildFixed()
	return ap
}



func (ap *ArpPacket) buildFixed() {
	ap.etherHdr.setArpType()

	ap.arpHdr[0] = 0x00   // HTYPE = 1 (Ethernet) - big endian
	ap.arpHdr[1] = 0x01
	ap.arpHdr[2] = 0x08   // PTYPE = 0x0800 (IPv4) - big endian
	ap.arpHdr[3] = 0x00
	ap.arpHdr[4] = 0x06   // HLEN = 6
	ap.arpHdr[5] = 0x04   // PLEN = 4
	ap.arpHdr[6] = 0x00   // OPER = 1 (request) - big endian
	ap.arpHdr[7] = 0x01
	// THA (6 bytes, 18:24) - zero 
}



func (ap *ArpPacket) AddReqStaticAddrs(
	srcMac  net.HardwareAddr,
	srcIP   net.IP,
) {
	ap.etherHdr.setDstAddr(net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	ap.etherHdr.setSrcAddr(srcMac)
	ap.copyEtherHdr()

	// 0:8 - fixed
	ipv4 := conv.MustTo4(srcIP)
	copy(ap.arpHdr[8:14], srcMac)
	copy(ap.arpHdr[14:18], ipv4)
	// 18:24 - fixed
}



func (ap *ArpPacket) copyEtherHdr() {
	copy(ap.buffer[:14], ap.etherHdr.header[:])
}



func (ap *ArpPacket) copyArpHdr() {
	copy(ap.buffer[14:], ap.arpHdr[:])
}



func (ap *ArpPacket) L3ReqPkt(dstIP net.IP) []byte {
	ipv4 := conv.MustTo4(dstIP)
	copy(ap.arpHdr[24:28], ipv4)
	ap.copyArpHdr()
	
	return ap.buffer[:]
}