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
	"offscan/internal/conv"
)


type ArpPacket struct {
	buffer     [42]byte
	arpHdr    *[28]byte
	etherHdr   etherHeader
}



func NewArpPkt() *ArpPacket {
	ap := &ArpPacket{ etherHdr: newEtherHeader() }
	ap.refBuffer()
	ap.buildFixed()
	return ap
}



func (ap *ArpPacket) refBuffer() {
	ap.etherHdr.header = (*[14]byte)(ap.buffer[0:14])
	ap.arpHdr          = (*[28]byte)(ap.buffer[14:42])
}



func (ap *ArpPacket) buildFixed() {
	ap.etherHdr.setArpType()
	ap.setHardwareType()
	ap.setProtocolType()
	ap.setHardwareAddrLen()
	ap.setProtocolAddrLen()
}



func (ap *ArpPacket) setHardwareType() {
	binary.BigEndian.PutUint16(ap.arpHdr[0:2], 0x0001) // HTYPE = 1 (Ethernet)
}



func (ap *ArpPacket) setProtocolType() {
	binary.BigEndian.PutUint16(ap.arpHdr[2:4], 0x0800) // PTYPE = 0x0800 (IPv4)
}



func (ap *ArpPacket) setHardwareAddrLen() {
	ap.arpHdr[4] = 0x06
}



func (ap *ArpPacket) setProtocolAddrLen() {
	ap.arpHdr[5] = 0x04
}



func (ap *ArpPacket) setOpcode(opcode uint16) {
	binary.BigEndian.PutUint16(ap.arpHdr[6:8], opcode)
}



func (ap *ArpPacket) setRequestIP(ip net.IP) {
	ipv4 := conv.MustTo4(ip)
	copy(ap.arpHdr[24:28], ipv4)
}



func (ap *ArpPacket) SetRequestStatic(
	srcMac  net.HardwareAddr,
	srcIP   net.IP,
) {
	ap.etherHdr.SetDstAddr(net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	ap.etherHdr.SetSrcAddr(srcMac)

	ap.setOpcode(0x0001)
	ipv4 := conv.MustTo4(srcIP)
	copy(ap.arpHdr[8:14], srcMac)
	copy(ap.arpHdr[14:18], ipv4)
}



func (ap *ArpPacket) SetReplyStatic() {
	ap.setOpcode(0x0002)
}



func (ap *ArpPacket) RequestPkt(dstIP net.IP) []byte {
	ap.setRequestIP(dstIP)	
	return ap.buffer[:]
}



func (ap *ArpPacket) ReplyPkt(
	dstMAC, srcMAC net.HardwareAddr,

) []byte {
	return ap.buffer[:]
}