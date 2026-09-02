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



func (pd *PacketDissector) GetEtherSrcMAC() (models.MAC, bool) {
    var mac models.MAC

    if pd.lenPkt < 12 {
        return mac, false
    }

    copy(mac[:], pd.pkt[6:12])
    
	return mac, true
}



func (pd *PacketDissector) getEtherType() uint16 {
    if pd.lenPkt < 14 { return 0 }
    return (uint16(pd.pkt[12]) << 8) | uint16(pd.pkt[13])
}