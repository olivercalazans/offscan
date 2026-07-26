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

package dot11dissec



func (dd *Dot11Dissector) checkIfIsDataFrame() bool {
    if len(dd.frame) < 24 { return false }

    frameControl := dd.frame[0]
    fType        := (frameControl >> 2) & 0x03

    if fType != 2 { return false }

	dd.IsDataFrm = true
    return true
}



func (dd *Dot11Dissector) GetAddrs() ([6]byte, [6]byte, bool) {
    var addr1, addr2 [6]byte
    toDS, fromDS := dd.getDSFlags()

    if (toDS && fromDS) || (!toDS && !fromDS) {
        return addr1, addr2, false
    }

    addr1 = dd.getAddr1()
    addr2 = dd.getAddr2()

    if toDS { return addr1, addr2, isValid(addr2)}

	return addr2, addr1, isValid(addr1)
}



func (dd *Dot11Dissector) getDSFlags() (bool, bool) {
    if len(dd.frame) < 2 { return false, false }

    flags  := dd.frame[1]
    toDS   := (flags >> 0) & 0x01
    fromDS := (flags >> 1) & 0x01

    return toDS == 1, fromDS == 1
}



func (dd *Dot11Dissector) getAddr1() [6]byte {
	var addr [6]byte
	copy(addr[:], dd.frame[4:10])
	return addr
}



func (dd *Dot11Dissector) getAddr2() [6]byte {
	var addr [6]byte
	copy(addr[:], dd.frame[10:16])
	return addr
}



func isValid(mac [6]byte) bool {
	// Multicast IPv4
    if mac[0] == 0x01 && mac[1] == 0x00 { return false }

    // Multicast IPv6
	if mac[0] == 0x33 && mac[1] == 0x33 { return false }
	
    // Multicast (STP)
    if mac[0] == 0x01 && mac[1] == 0x80 && mac[2] == 0xc2 { return false }
	
    // Broadcast
    if mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff { return false }

	return true
}