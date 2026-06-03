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
	"encoding/binary"
	"net"
)



type ipHeader struct {
	header  *[20]byte
}



func newIpHeader(header *[20]byte) ipHeader {
	ih := ipHeader{ header: header }
	ih.fixedIpInfo()
	return ih
}



func (iph *ipHeader) fixedIpInfo() {
	iph.header[0] = (4 << 4) | 5                          // Version + IHL
	iph.header[1] = 0                                     // DSCP + ECN
	binary.BigEndian.PutUint16(iph.header[4:6], 0x1234)   // ID
	binary.BigEndian.PutUint16(iph.header[6:8], 0x4000)   // Flags + Fragment offset (bit DF = 1, offset 0)
	iph.header[8] = 64									  // TTL
	binary.BigEndian.PutUint16(iph.header[10:12], 0)      // Checksum
}



func (iph *ipHeader) setLen(layer4Len uint16) {
	binary.BigEndian.PutUint16(iph.header[2:4], 20 + layer4Len)
}



func (iph *ipHeader) setProto(proto uint8) {
	iph.header[9] = proto
}



func (iph *ipHeader) calculateChecksum() {
	ck := Ipv4Sum(iph.header[0:20])
	binary.BigEndian.PutUint16(iph.header[10:12], ck)
}



func (iph *ipHeader) setSrcIp(srcIp net.IP) {
	src := srcIp.To4()
	if src == nil{
		return
	}

	copy(iph.header[12:16], src)
}



func (iph *ipHeader) setDstIp(dstIp net.IP) {
	dst := dstIp.To4()
	if dst == nil {
		return
	}

	copy(iph.header[16:20], dst)
}