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

// alignment: 8 bytes
type PacketDissector struct {
    pkt           []byte  // 24 bytes
    lenPkt        int     //  8 bytes
    isIPv4        bool    //  1 byte
    isArpReply    bool    //  1 byte
    isArpRequest  bool    //  1 byte
    isDHCP        bool    //  1 byte
    // padding: 4 bytes
}



func NewPacketDissector() *PacketDissector {
    return &PacketDissector{ pkt: make([]byte, 0) }
}



func (pd *PacketDissector) UpdatePkt(rawPkt []byte) {
    pd.lenPkt = len(rawPkt)
    pd.pkt    = rawPkt
    pd.resetFlags()
}



func (pd *PacketDissector) resetFlags() {
    pd.isIPv4       = false
	pd.isArpReply   = false
	pd.isArpRequest = false
    pd.isDHCP       = false
}