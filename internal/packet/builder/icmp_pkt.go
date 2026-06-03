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


type IcmpPacket struct {
	buffer  [28]byte
	ipHdr   ipHeader
	offset  uint8
}



func NewIcmpPkt() IcmpPacket {
	return IcmpPacket{}
}



func (ip *IcmpPacket) Init() {
	ip.ipHdr  = newIpHeader() 
	ip.offset = 20
	ip.buildFixed()
}



func (ip *IcmpPacket) buildFixed() {
	ip.ipHdr.fixedIpInfo()
	ip.ipHdr.setProto(1)
	ip.ipHdr.setLen(8)

	ip.buffer[ip.offset]     = 8
	ip.buffer[ip.offset + 1] = 0
	
	binary.BigEndian.PutUint16(ip.buffer[ip.offset + 2 : ip.offset + 4], 0)
	binary.BigEndian.PutUint16(ip.buffer[ip.offset + 4 : ip.offset + 6], 0x1234)
	binary.BigEndian.PutUint16(ip.buffer[ip.offset + 6 : ip.offset + 8], 1)

	ck := icmpSum(ip.buffer[ip.offset : ip.offset + 8])
	binary.BigEndian.PutUint16(ip.buffer[ip.offset + 2 : ip.offset + 4], ck)
}




func (ip *IcmpPacket) L3PingPkt(srcIP, dstIP net.IP) []byte {
	ip.ipHdr.setSrcIp(srcIP)
	ip.ipHdr.setDstIp(dstIP)
	ip.ipHdr.calculateChecksum()
	copy(ip.buffer[:20], ip.ipHdr.header[:])

	return ip.buffer[:28]
}