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

package pktdissec

import (
	"encoding/binary"
	"net"
)


func (pd *PacketDissector) checkIPv4() {
    if pd.lenPkt < 34 {
		pd.isIPv4 = false 
		return
	}

	ethertype := binary.BigEndian.Uint16(pd.pkt[12:14])
    pd.isIPv4  = ethertype == 0x0800
}



func (pd *PacketDissector) ihl() (uint8, bool) {
    if pd.lenPkt < 15 {
        return 0, false
    }

	ihl := pd.pkt[14] & 0x0F

	if ihl < 5 {
        return 0, false
    }

	return ihl, true
}



func (pd *PacketDissector) ipHeaderLen() (int, bool) {
    ihl, ok := pd.ihl()
    
	if !ok {
        return 0, false
    }
    
	return 14 + int(ihl)*4, true
}



func (pd *PacketDissector) GetSrcIP() (net.IP, bool) {
    if pd.lenPkt < 30 || !pd.isIPv4 {
        return nil, false
    }
    
	ip := net.IP(pd.pkt[26:30]).To4()
    
	if ip == nil {
        return nil, false
    }
    
	return ip, true
}



func (pd *PacketDissector) GetDstIP() (net.IP, bool) {
    if pd.lenPkt < 34 || !pd.isIPv4 {
        return nil, false
    }
    
	ip := net.IP(pd.pkt[30:34]).To4()
    
	if ip == nil {
        return nil, false
    }
    
	return ip, true
}