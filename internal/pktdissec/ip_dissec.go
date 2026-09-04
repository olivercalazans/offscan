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

import "offscan/internal/models"


func (pd *PacketDissector) IsIPv4() bool {
    pd.isIPv4 = pd.lenPkt >= 34 && pd.getEtherType() == 0x0800
    return pd.isIPv4
}



func (pd *PacketDissector) GetSrcIP() (models.IPv4, bool) {
    var ip models.IPv4

    if pd.lenPkt < 30 || !pd.isIPv4 {
        return ip, false
    }
    
	copy(ip[:], pd.pkt[26:30])
    
	return ip, true
}