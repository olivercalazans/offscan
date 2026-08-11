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

import "encoding/binary"



type Dot11Dissector struct {
	frame       []byte
	dot11Start  int
	IsBeacon    bool
	IsDataFrm   bool
	ieCache     map[uint8][]byte
	wpa1Data    []byte
	wpsData     []byte
	timestamp   uint64
	wpsInfo     WPSInfo
}



func NewDot11Dissector() *Dot11Dissector {
	return &Dot11Dissector{
		ieCache: make(map[uint8][]byte),
		wpsInfo: WPSInfo{
			str: make([]string, 0),
		},
	}
}



func (dd *Dot11Dissector) UpdatePkt(frame []byte) {
	dd.frame = frame
	dd.reset()
	dd.removeRadiotap()
	dd.checkFrameType()
	if dd.IsBeacon { dd.cacheIEs() }
}



func (dd *Dot11Dissector) reset() {
	dd.dot11Start = 0
	dd.IsBeacon   = false
	dd.IsDataFrm  = false
	dd.ieCache    = make(map[uint8][]byte)
	dd.wpa1Data   = nil
	dd.wpsData    = nil
	dd.timestamp  = 0
}



func (dd *Dot11Dissector) removeRadiotap() {
	if len(dd.frame) < 4 || dd.frame[0] != 0x00 {
		return
	}

	rtLen := int(binary.LittleEndian.Uint16(dd.frame[2:4]))
	if rtLen > 0 && rtLen < len(dd.frame) {
		dd.frame = dd.frame[rtLen:]
	}
}



func (dd *Dot11Dissector) checkFrameType() {
	if dd.checkIfIsBeacon() { return }
	if dd.checkIfIsDataFrame() { return }
}


func (dd *Dot11Dissector) cacheIEs() {
	lenFrm := len(dd.frame)

	if !dd.IsBeacon || lenFrm < 36 {
		return
	}

	if lenFrm >= 32 {
		dd.timestamp = binary.LittleEndian.Uint64(dd.frame[24:32])
	}

	offset := 36
	for offset+2 <= lenFrm {
		ieID  := dd.frame[offset]
		ieLen := int(dd.frame[offset+1])
		
		if offset+2+ieLen > lenFrm {
			break
		}
		
		data := dd.frame[offset+2 : offset+2+ieLen]
		dd.ieCache[ieID] = data

		if ieID == 0xDD && ieLen >= 4 {
			oui     := data[0:3]
			ouiType := data[3]

			if oui[0] == 0x00 && oui[1] == 0x50 && oui[2] == 0xF2 {
				switch ouiType {
				case 0x01: dd.wpa1Data = data[4:] // WPA1
				case 0x04: dd.wpsData  = data[4:] // WPS
				}
			}
		}

		offset += 2 + ieLen
	}
}