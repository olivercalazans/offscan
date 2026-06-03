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
    buffer     [40]byte
    ipLayer    ipHeader
    tcpLayer  *[20]byte
}



func NewTcpPkt() TcpPacket {
   return TcpPacket{}
}



func (tp *TcpPacket) Init() {
    tp.ipLayer  = newIpHeader((*[20]byte)(tp.buffer[0:20]))
    tp.tcpLayer = (*[20]byte)(tp.buffer[20:40])
    tp.buildFixed()
}



func (tp *TcpPacket) buildFixed() {
    tp.ipLayer.fixedIpInfo()
	tp.ipLayer.setProto(6)
	tp.ipLayer.setLen(20)

    binary.BigEndian.PutUint32(tp.tcpLayer[4:8], 1)
    binary.BigEndian.PutUint32(tp.tcpLayer[8:12], 0)
    
    tp.tcpLayer[12] = 5 << 4
    tp.tcpLayer[13] = 0x02
    
    binary.BigEndian.PutUint16(tp.tcpLayer[14:16], 64240)
    binary.BigEndian.PutUint16(tp.tcpLayer[18:20], 0)
}



func (tp *TcpPacket) setSrcPort(srcPort uint16) {
    binary.BigEndian.PutUint16(tp.tcpLayer[0:2], srcPort)
}



func (tp *TcpPacket) setDstPort(dstPort uint16) {
    binary.BigEndian.PutUint16(tp.tcpLayer[2:4], dstPort)
}



func (tp *TcpPacket) flushChecksum() {
    binary.BigEndian.PutUint16(tp.tcpLayer[16:18], 0)
}



func (tp *TcpPacket) calculateChecksum(srcIp, dstIp net.IP) {
    cksum := TcpSum(tp.tcpLayer[:20], srcIp, dstIp, 6)
    binary.BigEndian.PutUint16(tp.tcpLayer[16:18], cksum)
}



func (tp *TcpPacket) L3SynPkt(
	srcIP   net.IP, 
	srcPort uint16, 
	dstIP   net.IP, 
	dstPort uint16,
) []byte {
    tp.ipLayer.setSrcIp(srcIP)
    tp.ipLayer.setDstIp(dstIP)
    tp.ipLayer.calculateChecksum()

    tp.setSrcPort(srcPort)
    tp.setDstPort(dstPort)
    tp.flushChecksum()
    tp.calculateChecksum(srcIP, dstIP)
    
    return tp.buffer[:40]
}