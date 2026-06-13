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



type PacketDissector struct {
    pkt     []byte
    isARP   bool
    lenPkt  int
}



func NewPacketDissector() *PacketDissector {
    return &PacketDissector{
        pkt: make([]byte, 0),
    }
}



func (pd *PacketDissector) UpdatePkt(rawPkt []byte) bool {
    pd.lenPkt = len(rawPkt)

	if pd.lenPkt < 28 { return false }

    pd.pkt = rawPkt
    pd.isArpReply()
	
	return true
}



func (pd *PacketDissector) isIPv4() bool {
    if pd.lenPkt < 14 {
        return false
    }

	ethertype := binary.BigEndian.Uint16(pd.pkt[12:14])
    return ethertype == 0x0800
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



func (pd *PacketDissector) isArpReply() {
	if pd.lenPkt < 42 {
		pd.isARP = false
		return
	}

	etherType := (uint16(pd.pkt[12]) << 8) | uint16(pd.pkt[13])
	if etherType != 0x0806 {
		pd.isARP = false
		return
	}

	operation := (uint16(pd.pkt[20]) << 8) | uint16(pd.pkt[21])
	if operation != 2 {
		pd.isARP = false
		return
	}

    pd.isARP = true
}



func (pd *PacketDissector) isTCP() bool {
    if pd.lenPkt < 24 {
        return false
    }
    
	return pd.pkt[23] == 6
}



func (pd *PacketDissector) GetSrcMac() (net.HardwareAddr, bool) {
    if pd.isARP {
        return net.HardwareAddr(pd.pkt[22:28]), true
    }

    if pd.lenPkt < 12 || !pd.isIPv4() {
        return nil, false
    }
    
	return net.HardwareAddr(pd.pkt[6:12]), true
}



func (pd *PacketDissector) GetSrcIP() (net.IP, bool) {
    if pd.isARP {
        return net.IP(pd.pkt[28:32]), true
    }

    if pd.lenPkt < 30 || !pd.isIPv4() {
        return nil, false
    }
    
	ip := net.IP(pd.pkt[26:30]).To4()
    
	if ip == nil {
        return nil, false
    }
    
	return ip, true
}



func (pd *PacketDissector) GetDstIP() (net.IP, bool) {
    if pd.isARP {
        return net.IP{}, false
    }

    if pd.lenPkt < 30 || !pd.isIPv4() {
        return nil, false
    }
    
	ip := net.IP(pd.pkt[30:34]).To4()
    
	if ip == nil {
        return nil, false
    }
    
	return ip, true
}



func (pd *PacketDissector) GetTcpSrcPort() (uint16, bool) {
    if pd.lenPkt < 54 || !pd.isIPv4() || !pd.isTCP() {
        return 0, false
    }

	offset, ok := pd.ipHeaderLen()
    if !ok {
        return 0, false
    }

	if pd.lenPkt < offset+2 {
        return 0, false
    }

	port := binary.BigEndian.Uint16(pd.pkt[offset : offset+2])
    return port, true
}