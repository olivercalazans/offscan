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
	"fmt"
	"net"
	"offscan/internal/utils"
)



type ipHeader struct {
	header  []byte
}



func newIpHeader(header []byte) *ipHeader {
	var headerLen uint8 = uint8(len(header))
	if headerLen > 20 {
		utils.Abort(fmt.Sprintf("Header bigger than 20. Header len: %d", headerLen))
	}

	ih := &ipHeader{ header: header }
	ih.fixedIpInfo()
	return ih
}


func (ih *ipHeader) fixedIpInfo() {
	ih.header[0] = (4 << 4) | 5                          // Version + IHL
	ih.header[1] = 0                                     // DSCP + ECN
	binary.BigEndian.PutUint16(ih.header[4:6], 0x1234)   // ID
	binary.BigEndian.PutUint16(ih.header[6:8], 0x4000)   // Flags + Fragment offset (bit DF = 1, offset 0)
	ih.header[8] = 64									 // TTL
	binary.BigEndian.PutUint16(ih.header[10:12], 0)      // Checksum
}



func (ih *ipHeader) setLen(lenUpperHdr uint16) {
	binary.BigEndian.PutUint16(ih.header[2:4], 20 + lenUpperHdr)
}



func (ih *ipHeader) setProto(proto uint8) {
	ih.header[9] = proto
}



func (ih *ipHeader) updateChecksum() {
	ck := Ipv4Sum(ih.header[0:20])
	binary.BigEndian.PutUint16(ih.header[10:12], ck)
}



func (ih *ipHeader) updateSrcIp(srcIp net.IP) {
	src := srcIp.To4()
	if src == nil{
		return
	}

	copy(ih.header[12:16], src)
}



func (ih *ipHeader) updateDstIp(dstIp net.IP) {
	dst := dstIp.To4()
	if dst == nil {
		return
	}

	copy(ih.header[16:20], dst)
}