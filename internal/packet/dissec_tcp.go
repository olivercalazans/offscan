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

import "encoding/binary"



func (pd *PacketDissector) isTCP() bool {
    if pd.lenPkt < 24 {
        return false
    }
    
	return pd.pkt[23] == 6
}



func (pd *PacketDissector) GetTcpSrcPort() (uint16, bool) {
    if pd.lenPkt < 54 || !pd.isIPv4 || !pd.isTCP() {
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