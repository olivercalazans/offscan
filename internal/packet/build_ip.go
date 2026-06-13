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
	"offscan/internal/conv"
)



type ipHeader struct {
	header  *[20]byte
}



const lenIPHdr int = 20



func newIpHeader() ipHeader {
	iph := ipHeader{}
	return iph
}



func (iph *ipHeader) buildFixed() {
	iph.setVersionAndIHL()
	iph.setDSCPAndECN()
	iph.setID()
	iph.setFlagsAndFragOffset()
	iph.setTTL()
}



func (iph *ipHeader) setVersionAndIHL() {
	iph.header[0] = (4 << 4) | 5
}



func (iph *ipHeader) setDSCPAndECN() {
	iph.header[1] = 0
}



func (iph *ipHeader) setLen(layer4Len uint16) {
	binary.BigEndian.PutUint16(iph.header[2:4], uint16(lenIPHdr) + layer4Len)
}



func (iph *ipHeader) setID() {
	binary.BigEndian.PutUint16(iph.header[4:6], 0x1234)
}



func (iph *ipHeader) setFlagsAndFragOffset() {
	// Flags + Fragment offset (bit DF = 1, offset 0)
	binary.BigEndian.PutUint16(iph.header[6:8], 0x4000)
}



func (iph *ipHeader) setTTL() {
	iph.header[8] = 64
}



func (iph *ipHeader) setProto(proto uint8) {
	iph.header[9] = proto
}



func (iph *ipHeader) calculateChecksum() {
	binary.BigEndian.PutUint16(iph.header[10:12], 0)
	ck := iph.calcCksum()
	binary.BigEndian.PutUint16(iph.header[10:12], ck)
}



func (iph *ipHeader) calcCksum() uint16 {
    var sum uint32 = 0
    i := 0

	for i+1 < lenIPHdr {
        sum += (uint32(iph.header[i]) << 8) | uint32(iph.header[i+1])
        i += 2
    }

	if i < lenIPHdr {
        sum += uint32(iph.header[i]) << 8
    }

	for (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }

	return ^uint16(sum)
}



func (iph *ipHeader) SetSrcIP(srcIP net.IP) {
	ipv4 := conv.MustTo4(srcIP)
	copy(iph.header[12:16], ipv4)
}



func (iph *ipHeader) SetDstIP(dstIP net.IP) {
	ipv4 := conv.MustTo4(dstIP)
	copy(iph.header[16:20], ipv4)
}