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

package pktbuilder

import (
	"encoding/binary"
	"net"
)



type TcpPkt struct {
    buffer    [40]byte
    ipLayer  *ipHeader
    tcpLayer *[20]byte
}



func NewTcpPkt() *TcpPkt {
    t := &TcpPkt{}
    
    t.ipLayer  = newIpHeader(t.buffer[:20])
    t.tcpLayer = (*[20]byte)(t.buffer[20:40])
	
    t.buildFixed()
    
    return t
}



func (t *TcpPkt) buildFixed() {
    t.ipLayer.fixedIpInfo()
	t.ipLayer.setProto(6)
	t.ipLayer.setLen(20)

    binary.BigEndian.PutUint32(t.tcpLayer[4:8], 1)
    binary.BigEndian.PutUint32(t.tcpLayer[8:12], 0)
    
    t.tcpLayer[12] = 5 << 4
    t.tcpLayer[13] = 0x02
    
    binary.BigEndian.PutUint16(t.tcpLayer[14:16], 64240)
    binary.BigEndian.PutUint16(t.tcpLayer[18:20], 0)
}



func (t *TcpPkt) updateSrcPort(srcPort uint16) {
    binary.BigEndian.PutUint16(t.tcpLayer[0:2], srcPort)
}



func (t *TcpPkt) updateDstPort(dstPort uint16) {
    binary.BigEndian.PutUint16(t.tcpLayer[2:4], dstPort)
}



func (t *TcpPkt) flushChecksum() {
    binary.BigEndian.PutUint16(t.tcpLayer[16:18], 0)
}



func (t *TcpPkt) updateChecksum(srcIp, dstIp net.IP) {
    cksum := TcpUdpSum(t.tcpLayer[:20], srcIp, dstIp, 6)
    binary.BigEndian.PutUint16(t.tcpLayer[16:18], cksum)
}



func (t *TcpPkt) L3Pkt(
	srcIP   net.IP, 
	srcPort uint16, 
	dstIP   net.IP, 
	dstPort uint16,
) []byte {
    t.ipLayer.updateSrcIp(srcIP)
    t.ipLayer.updateDstIp(dstIP)
    t.ipLayer.updateChecksum()

    t.updateSrcPort(srcPort)
    t.updateDstPort(dstPort)
    t.flushChecksum()
    t.updateChecksum(srcIP, dstIP)
    
    return t.buffer[:40]
}