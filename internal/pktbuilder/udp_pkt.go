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



type UdpPkt struct {
    buffer [347]byte
}



func NewUdpPkt() *UdpPkt {
    p := &UdpPkt{}
    p.buildFixed()
    return p
}



func (p *UdpPkt) buildFixed() {
    // IP header (bytes 0-20)
    p.buffer[0] = (4 << 4) | 5
    p.buffer[1] = 0
    binary.BigEndian.PutUint16(p.buffer[4:6], 0x1234)
    binary.BigEndian.PutUint16(p.buffer[6:8], 0x4000)
    p.buffer[8] = 64
    p.buffer[9] = 17
}



func (p *UdpPkt) ipHeader(
    totalLen uint16, 
    srcIP    net.IP, 
    dstIP    net.IP,
) {
    // 0:9 - fixed
    binary.BigEndian.PutUint16(p.buffer[2:4], totalLen)
    binary.BigEndian.PutUint16(p.buffer[10:12], 0)
    src := srcIP.To4()
    dst := dstIP.To4()
    
	if src == nil || dst == nil {
        return
    }
    copy(p.buffer[12:16], src)
    copy(p.buffer[16:20], dst)

    ck := Ipv4Sum(p.buffer[:20])
    binary.BigEndian.PutUint16(p.buffer[10:12], ck)
}



func (p *UdpPkt) udpHeader(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, payloadLen uint16) {
    udpLen := 8 + payloadLen

    binary.BigEndian.PutUint16(p.buffer[20:22], srcPort)
    binary.BigEndian.PutUint16(p.buffer[22:24], dstPort)
    binary.BigEndian.PutUint16(p.buffer[24:26], udpLen)
    binary.BigEndian.PutUint16(p.buffer[26:28], 0)

    udpSegment := p.buffer[20 : 20+udpLen]
    ck := TcpUdpSum(udpSegment, srcIP, dstIP, 17)
    binary.BigEndian.PutUint16(p.buffer[26:28], ck)
}



func (p *UdpPkt) L3Pkt(
	srcIP   net.IP, 
	srcPort uint16, 
	dstIP   net.IP, 
	dstPort uint16, 
	payload []byte,
) []byte {
    payloadLen := len(payload)
    
	if payloadLen > 347-28 {
        payloadLen = 347 - 28
        payload = payload[:payloadLen]
    }
    totalLen := 20 + 8 + payloadLen

    copy(p.buffer[28:28+payloadLen], payload)

    p.udpHeader(srcIP, srcPort, dstIP, dstPort, uint16(payloadLen))
    p.ipHeader(uint16(totalLen), srcIP, dstIP)

    return p.buffer[:totalLen]
}