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



func (pd *PacketDissector) IsArpReply() bool {
	return pd.isArpReply
}



func (pd *PacketDissector) IsArpRequest() bool {
	return pd.isArpRequest
}



func (pd *PacketDissector) IsARP() bool {
	if pd.lenPkt < 42 {
		return false
	}

	if pd.getEtherType() != 0x0806 {
		return false
	}

	pd.checkArpOpcode()
	return true
}



func (pd *PacketDissector) checkArpOpcode() {
	opCode := (uint16(pd.pkt[20]) << 8) | uint16(pd.pkt[21])
	
	pd.isArpRequest = opCode == 1
    pd.isArpReply   = opCode == 2
}



func (pd *PacketDissector) GetArpSrcIP() ([4]byte, bool) {
	var ip [4]byte

	if pd.lenPkt < 32 {
		return ip, false 
	}

	copy(ip[:], pd.pkt[28:32])
	
	return ip, true
}



func (pd *PacketDissector) GetArpSrcMAC() ([6]byte, bool) {
	var mac [6]byte
	
	if pd.lenPkt < 28 {
		return mac, false
	}

	copy(mac[:], pd.pkt[22:28])

	return mac, true
}