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



type TcpPacket struct {
    buffer  [40]byte
    tcpHdr  [20]byte
    ipHdr   ipHeader
}



func NewTcpPkt() TcpPacket {
   return TcpPacket{}
}



func (tp *TcpPacket) Init() {
    tp.ipHdr  = newIpHeader()
    tp.buildFixed()
}



func (tp *TcpPacket) buildFixed() {
    tp.ipHdr.fixedIpInfo()
	tp.ipHdr.setProto(6)
	tp.ipHdr.setLen(20)

    binary.BigEndian.PutUint32(tp.tcpHdr[4:8], 1)
    binary.BigEndian.PutUint32(tp.tcpHdr[8:12], 0)
    
    tp.tcpHdr[12] = 5 << 4
    tp.tcpHdr[13] = 0x02
    
    binary.BigEndian.PutUint16(tp.tcpHdr[14:16], 64240)
    binary.BigEndian.PutUint16(tp.tcpHdr[18:20], 0)
}



func (tp *TcpPacket) setSrcPort(srcPort uint16) {
    binary.BigEndian.PutUint16(tp.tcpHdr[0:2], srcPort)
}



func (tp *TcpPacket) setDstPort(dstPort uint16) {
    binary.BigEndian.PutUint16(tp.tcpHdr[2:4], dstPort)
}



func (tp *TcpPacket) flushChecksum() {
    binary.BigEndian.PutUint16(tp.tcpHdr[16:18], 0)
}



func (tp *TcpPacket) calculateChecksum(srcIp, dstIp net.IP) {
    cksum := tcpSum(tp.tcpHdr[:20], srcIp, dstIp, 6)
    binary.BigEndian.PutUint16(tp.tcpHdr[16:18], cksum)
}



func (tp *TcpPacket) L3SynPkt(
	srcIP   net.IP, 
	srcPort uint16, 
	dstIP   net.IP, 
	dstPort uint16,
) []byte {
    tp.ipHdr.setSrcIp(srcIP)
    tp.ipHdr.setDstIp(dstIP)
    tp.ipHdr.calculateChecksum()
    copy(tp.buffer[:20], tp.ipHdr.header[:])

    tp.setSrcPort(srcPort)
    tp.setDstPort(dstPort)
    tp.flushChecksum()
    tp.calculateChecksum(srcIP, dstIP)
    copy(tp.buffer[:], tp.tcpHdr[:])
    
    return tp.buffer[:40]
}