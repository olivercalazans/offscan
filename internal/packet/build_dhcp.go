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
	"net"
)



type DHCPHeader struct {
	buffer  [277]byte
	offset  int
}



func NewDHCPHeader() DHCPHeader {
	dh := DHCPHeader{}
	return dh
}



func (dh *DHCPHeader) buildFixed() {
	dh.setOp()
	dh.setHType()
	dh.setHLen()
	dh.setMagicCookie()
}



func (dh *DHCPHeader) setOp() {
	dh.buffer[0] = 2
}



func (dh *DHCPHeader) setHType() {
	dh.buffer[1] = 1
}



func (dh *DHCPHeader) setHLen() {
	dh.buffer[2] = 6
}



func (dh *DHCPHeader) setHops() {
	dh.buffer[3] = 0
}



func (dh *DHCPHeader) SetXID(xid uint32) {
	binary.BigEndian.PutUint32(dh.buffer[4:8], xid)
}



func (dh *DHCPHeader) SetFlags(flags uint16) {
	binary.BigEndian.PutUint16(dh.buffer[10:12], flags)
}



func (dh *DHCPHeader) SetCIAddr(ip net.IP) {
	copy(dh.buffer[12:16], ip)
}



func (dh *DHCPHeader) SetYIAddr(ip net.IP) {
	copy(dh.buffer[16:20], ip)
}



func (dh *DHCPHeader) SetSIAddr(ip net.IP) {
	copy(dh.buffer[20:24], ip)
}



func (dh *DHCPHeader) SetGIAddr(ip net.IP) {
	copy(dh.buffer[24:28], ip)
}



func (dh *DHCPHeader) SetCHAddr(mac net.HardwareAddr) {
	copy(dh.buffer[28:34], mac)
}



func (dh *DHCPHeader) setMagicCookie() {
	dh.buffer[236] = 0x63
	dh.buffer[237] = 0x82
	dh.buffer[238] = 0x53
	dh.buffer[239] = 0x63
}



func (dh *DHCPHeader) FlushOptions() {
	clear(dh.buffer[240:])
	dh.offset = 240
}



func (dh *DHCPHeader) SetOfferMsg() {
	dh.buffer[dh.offset]     = 53
	dh.buffer[dh.offset + 1] = 1
	dh.buffer[dh.offset + 2] = 2
	dh.offset += 3
}



func (dh *DHCPHeader) SetMask() {
	dh.buffer[dh.offset]     = 1
	dh.buffer[dh.offset + 1] = 4
	dh.buffer[dh.offset + 2] = 255
	dh.buffer[dh.offset + 3] = 255
	dh.buffer[dh.offset + 4] = 255
	dh.buffer[dh.offset + 5] = 0
	dh.offset += 6
}



func (dh *DHCPHeader) SetGateway(ip net.IP) {
	dh.buffer[dh.offset]     = 3
	dh.buffer[dh.offset + 1] = 4
	dh.offset += 2

	copy(dh.buffer[dh.offset : dh.offset + 4], ip)
	dh.offset += 4
}



func (dh *DHCPHeader) SetDNS(ip net.IP) {
	dh.buffer[dh.offset]     = 6
	dh.buffer[dh.offset + 1] = 4
	dh.offset += 2

	copy(dh.buffer[dh.offset : dh.offset + 4], ip)
	dh.offset += 4
}



func (dh *DHCPHeader) SetLeaseTime() {
	dh.buffer[dh.offset]     = 51
	dh.buffer[dh.offset + 1] = 4
	dh.offset += 2

	binary.BigEndian.PutUint32(dh.buffer[dh.offset : dh.offset + 4], 86400)
	dh.offset += 4
}



func (dh *DHCPHeader) SetEnd() {
	dh.buffer[dh.offset] = 255
	dh.offset++
}



func (dh *DHCPHeader) Header() []byte {
	return dh.buffer[:dh.offset]
}