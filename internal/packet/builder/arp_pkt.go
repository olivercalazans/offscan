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
	EtherHdr   etherHeader
}



func NewArpPkt() *ArpPacket {
	ap := &ArpPacket{ EtherHdr: etherHeader{} }
	ap.refBuffer()
	return ap
}



func (ap *ArpPacket) refBuffer() {
	ap.EtherHdr.header = (*[14]byte)(ap.buffer[0:14])
	ap.arpHdr          = (*[28]byte)(ap.buffer[14:42])
}



func (ap *ArpPacket) SetHardwareType() {
	binary.BigEndian.PutUint16(ap.arpHdr[0:2], 0x0001) // HTYPE = 1 (Ethernet)
}



func (ap *ArpPacket) SetProtocolType() {
	binary.BigEndian.PutUint16(ap.arpHdr[2:4], 0x0800) // PTYPE = 0x0800 (IPv4)
}



func (ap *ArpPacket) SetHardwareAddrLen() {
	ap.arpHdr[4] = 0x06
}



func (ap *ArpPacket) SetProtocolAddrLen() {
	ap.arpHdr[5] = 0x04
}



func (ap *ArpPacket) SetOpcode(opcode uint16) {
	binary.BigEndian.PutUint16(ap.arpHdr[6:8], opcode)
}



func (ap *ArpPacket) SetSenderMAC(mac net.HardwareAddr) {
	copy(ap.arpHdr[8:14], mac)
}



func (ap *ArpPacket) SetSenderIP(ip net.IP) {
	ipv4 := conv.MustTo4(ip)
	copy(ap.arpHdr[14:18], ipv4)
}



func (ap *ArpPacket) SetTargetMAC(mac net.HardwareAddr) {
	copy(ap.arpHdr[18:24], mac)
}



func (ap *ArpPacket) SetTargetIP(ip net.IP) {
	ipv4 := conv.MustTo4(ip)
	copy(ap.arpHdr[24:28], ipv4)
}



func (ap *ArpPacket) Pkt() []byte {
	return ap.buffer[:]
}