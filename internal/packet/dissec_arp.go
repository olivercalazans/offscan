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

import "net"



func (pd *PacketDissector) IsArpReply() bool {
	return pd.isArpReply
}



func (pd *PacketDissector) IsArpRequest() bool {
	return pd.isArpRequest
}



func (pd *PacketDissector) checkArpOpcode() bool {
	if pd.lenPkt < 42 {
		return false
	}

	etherType := (uint16(pd.pkt[12]) << 8) | uint16(pd.pkt[13])
	if etherType != 0x0806 {
		return false
	}

	opCode := (uint16(pd.pkt[20]) << 8) | uint16(pd.pkt[21])
	
	pd.isArpRequest = opCode == 1
    pd.isArpReply   = opCode == 2
	
	return true
}



func (pd *PacketDissector) GetArpSrcIP() (net.IP, bool) {
	if pd.lenPkt < 32 {
		return nil, false 
	}
	
	ipv4 := net.IP(pd.pkt[28:32]).To4()

	if ipv4 == nil {
		return nil, false
	}

	return ipv4, true
}



func (pd *PacketDissector) GetArpSrcMAC() (net.HardwareAddr, bool) {
	if pd.lenPkt < 28 {
		return nil, false
	}

	return net.HardwareAddr(pd.pkt[22:28]), true
}