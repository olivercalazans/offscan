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
	buffer    [28]byte
	icmpHdr  *[8]byte
	ipHdr     ipHeader
}



func NewIcmpPkt() *IcmpPacket {
	ip := &IcmpPacket{ ipHdr: newIpHeader() }
	ip.refBuffer()
	ip.buildFixed()

	return ip
}



func (ip *IcmpPacket) refBuffer() {
	ip.ipHdr.header = (*[20]byte)(ip.buffer[0:20])
	ip.icmpHdr      = (*[8]byte)(ip.buffer[20:28])
}



func (ip *IcmpPacket) buildFixed() {
	ip.ipHdr.fixedIpInfo()
	ip.ipHdr.setProto(1)
	ip.ipHdr.setLen(8)

	ip.setType()
	ip.setCode()
	ip.setID()
	ip.setSeqNum()
	ip.calculateChecksum()
}



func (ip *IcmpPacket) setType() {
	ip.icmpHdr[0] = 8
}



func (ip *IcmpPacket) setCode() {
	ip.icmpHdr[1] = 0
}


func (ip *IcmpPacket) calculateChecksum() {
	binary.BigEndian.PutUint16(ip.buffer[2:4], 0)
	ck := icmpSum(ip.buffer[0:8])
	binary.BigEndian.PutUint16(ip.buffer[2:4], ck)
}



func (ip *IcmpPacket) setID() {
	binary.BigEndian.PutUint16(ip.icmpHdr[4:6], 0x1234)
}



func (ip *IcmpPacket) setSeqNum() {
	binary.BigEndian.PutUint16(ip.icmpHdr[6:8], 1)
}



func (ip *IcmpPacket) L3PingPkt(srcIP, dstIP net.IP) []byte {
	ip.ipHdr.setSrcIp(srcIP)
	ip.ipHdr.setDstIp(dstIP)
	ip.ipHdr.calculateChecksum()

	return ip.buffer[:]
}