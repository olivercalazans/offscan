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
    buffer     [353]byte
    ipLayer   *ipHeader
    updLayer  *[333]byte
}



func NewUdpPkt() *UdpPkt {
    u := &UdpPkt{}

    u.ipLayer  = newIpHeader((*[20]byte)(u.buffer[0:20]))
    u.updLayer = (*[333]byte)(u.buffer[20:])
    
    u.buildFixed()
    return u
}



func (u *UdpPkt) buildFixed() {
    u.ipLayer.fixedIpInfo()
    u.ipLayer.setProto(17)
}



func (u *UdpPkt) setSrcPort(srcPort uint16) {
    binary.BigEndian.PutUint16(u.updLayer[0:2], srcPort)
}



func (u *UdpPkt) setDstPort(srcPort uint16) {
    binary.BigEndian.PutUint16(u.updLayer[2:4], srcPort)
}



func (u *UdpPkt) setLen(len uint16) {
    binary.BigEndian.PutUint16(u.updLayer[4:6], len)
}



func (u *UdpPkt) flushChecksum() {
    binary.BigEndian.PutUint16(u.updLayer[6:8], 0)
}



func (u *UdpPkt) calculateChecksum(
    srcIP   net.IP,
    dstIP   net.IP,
    lenUdp  uint16,
) {
    ck := TcpUdpSum(u.updLayer[:lenUdp], srcIP, dstIP, 17)
    binary.BigEndian.PutUint16(u.updLayer[6:8], ck)
}



func (u *UdpPkt) L3Pkt(
	srcIP    net.IP, 
	srcPort  uint16, 
	dstIP    net.IP, 
	dstPort  uint16, 
	payload  []byte,

) []byte {

    lenPayload := len(payload)
    lenUdp     := uint16(8 + lenPayload)
    totalLen   := uint16(20 + lenUdp)

    u.ipLayer.setLen(lenUdp)
    u.ipLayer.flushChecksum()
    u.ipLayer.setSrcIp(srcIP)
    u.ipLayer.setDstIp(dstIP)
    u.ipLayer.calculateChecksum()

    copy(u.updLayer[8:lenUdp], payload)
    u.setSrcPort(srcPort)
    u.setDstPort(dstPort)

    u.setSrcPort(srcPort)
    u.setDstPort(dstPort)
    u.setLen(lenUdp)
    u.flushChecksum()
    u.calculateChecksum(srcIP, dstIP, lenUdp)

    return u.buffer[:totalLen]
}