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
)


type IcmpPacket struct {
	buffer    [28]byte
	icmpHdr  *[8]byte
	IPHdr     ipHeader
}



const lenIcmpHdr int = 8



func NewIcmpPkt() *IcmpPacket {
	ip := &IcmpPacket{ IPHdr: newIpHeader() }
	ip.refBuffer()
	ip.buildFixed()

	return ip
}



func (ip *IcmpPacket) refBuffer() {
	ip.IPHdr.header = (*[20]byte)(ip.buffer[0:20])
	ip.icmpHdr      = (*[8]byte)(ip.buffer[20:28])
}



func (ip *IcmpPacket) buildFixed() {
	ip.IPHdr.buildFixed()
	ip.IPHdr.setProto(1)
	ip.IPHdr.setLen(uint16(lenIcmpHdr))

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
	ck := ip.calcCksum()
	binary.BigEndian.PutUint16(ip.buffer[2:4], ck)
}



func (ip *IcmpPacket) calcCksum() uint16 {
    var sum uint32 = 0
    i := 0

	for i+1 < lenIcmpHdr {
        sum += (uint32(ip.icmpHdr[i]) << 8) | uint32(ip.icmpHdr[i+1])
        i += 2
    }

	if i < lenIcmpHdr {
        sum += uint32(ip.icmpHdr[i]) << 8
    }

	for (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }

	return ^uint16(sum)
}



func (ip *IcmpPacket) setID() {
	binary.BigEndian.PutUint16(ip.icmpHdr[4:6], 0x1234)
}



func (ip *IcmpPacket) setSeqNum() {
	binary.BigEndian.PutUint16(ip.icmpHdr[6:8], 1)
}



func (ip *IcmpPacket) Pkt() []byte {
	ip.IPHdr.calculateChecksum()
	return ip.buffer[:]
}