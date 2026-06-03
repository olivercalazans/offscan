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
	buffer   [28]byte
	ipLayer  ipHeader
	offset   uint8
}



func NewIcmpPkt() IcmpPacket {
	return IcmpPacket{}
}



func (ip *IcmpPacket) Init() {
	ip.offset = 20
	ip.ipLayer = newIpHeader((*[20]byte)(ip.buffer[0:20]))
	ip.buildFixed()
}



func (i *IcmpPacket) buildFixed() {
	i.ipLayer.fixedIpInfo()
	i.ipLayer.setProto(1)
	i.ipLayer.setLen(8)

	i.buffer[i.offset]     = 8
	i.buffer[i.offset + 1] = 0
	
	binary.BigEndian.PutUint16(i.buffer[i.offset + 2 : i.offset + 4], 0)
	binary.BigEndian.PutUint16(i.buffer[i.offset + 4 : i.offset + 6], 0x1234)
	binary.BigEndian.PutUint16(i.buffer[i.offset + 6 : i.offset + 8], 1)

	ck := icmpSum(i.buffer[i.offset : i.offset + 8])
	binary.BigEndian.PutUint16(i.buffer[i.offset + 2 : i.offset + 4], ck)
}




func (i *IcmpPacket) L3PingPkt(srcIP, dstIP net.IP) []byte {
	i.ipLayer.setSrcIp(srcIP)
	i.ipLayer.setDstIp(dstIP)
	i.ipLayer.calculateChecksum()
	return i.buffer[:28]
}