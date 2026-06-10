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
)


const lenTcpHdr uint32 = 20


type TcpPacket struct {
    buffer   [40]byte
    tcpHdr  *[20]byte
    IPHdr    ipHeader
}



func NewTcpPkt() *TcpPacket {
   tp := &TcpPacket{ IPHdr: newIpHeader() }
   tp.refBuffer()
   tp.buildFixed()

   return tp
}



func (tp *TcpPacket) refBuffer() {
    tp.IPHdr.header = (*[20]byte)(tp.buffer[:20])
    tp.tcpHdr       = (*[20]byte)(tp.buffer[20:])
}



func (tp *TcpPacket) buildFixed() {
    tp.IPHdr.buildFixed()
	tp.IPHdr.setProto(6)
	tp.IPHdr.setLen(uint16(lenTcpHdr))

    tp.setSeqNum()
    tp.setAckNum()
    tp.setDataOffset()    
    tp.setCtrlFlags()
    tp.setWindowSize()
    tp.setUrgentPointer()
}



func (tp *TcpPacket) SetSrcPort(srcPort uint16) {
    binary.BigEndian.PutUint16(tp.tcpHdr[0:2], srcPort)
}



func (tp *TcpPacket) SetDstPort(dstPort uint16) {
    binary.BigEndian.PutUint16(tp.tcpHdr[2:4], dstPort)
}



func (tp *TcpPacket) setSeqNum() {
    binary.BigEndian.PutUint32(tp.tcpHdr[4:8], 1)
}



func (tp *TcpPacket) setAckNum() {
    binary.BigEndian.PutUint32(tp.tcpHdr[8:12], 0)
}



func (tp *TcpPacket) setDataOffset() {
    tp.tcpHdr[12] = 5 << 4
}



func (tp *TcpPacket) setCtrlFlags() {
    tp.tcpHdr[13] = 0x02
}



func (tp *TcpPacket) setWindowSize() {
    binary.BigEndian.PutUint16(tp.tcpHdr[14:16], 64240)
}



func (tp *TcpPacket) setUrgentPointer() {
    binary.BigEndian.PutUint16(tp.tcpHdr[18:20], 0)
}



func (tp *TcpPacket) calculateChecksum() {
    binary.BigEndian.PutUint16(tp.tcpHdr[16:18], 0)
    cksum := tp.calcCksum()
    binary.BigEndian.PutUint16(tp.tcpHdr[16:18], cksum)
}



func (tp *TcpPacket) Pkt() []byte {
    tp.IPHdr.calculateChecksum()
    tp.calculateChecksum()
    
    return tp.buffer[:]
}



func (tp *TcpPacket) calcCksum() uint16 {
    sum := tp.tcpSum()
    len := int(lenTcpHdr)
    i   := 0

	for i + 1 < len {
        sum += (uint32(tp.tcpHdr[i]) << 8) | uint32(tp.tcpHdr[i+1])
        i += 2
    }

	if i < len {
        sum += uint32(tp.tcpHdr[i]) << 8
    }

	for (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }

	return ^uint16(sum)
}



func (tp *TcpPacket) tcpSum() uint32 {
    var sum uint32 = 0

    // Source IP (12:16)
    sum += (uint32(tp.IPHdr.header[12]) << 8) | uint32(tp.IPHdr.header[13])
    sum += (uint32(tp.IPHdr.header[14]) << 8) | uint32(tp.IPHdr.header[15])

    // Destination IP (16:20)
	sum += (uint32(tp.IPHdr.header[16]) << 8) | uint32(tp.IPHdr.header[17])
    sum += (uint32(tp.IPHdr.header[18]) << 8) | uint32(tp.IPHdr.header[19])

    sum += uint32(6)
    sum += lenTcpHdr

    return sum
}