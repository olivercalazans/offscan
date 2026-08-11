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

import (
	"encoding/binary"
	"fmt"
	"strings"
)



func (dd *Dot11Dissector) GetWPS() string {
	if dd.wpsData == nil {
		return "?????"
	}
	
	wps := WPSInfo{}
	wps.parseWPS(dd.wpsData)
	wps.getVersion()
	wps.getState()
	wps.getMethods()
	wps.getLock()

	return strings.Join(wps.str, " ")
}



type WPSInfo struct {
	str            []string
	version        int
	state          int 
	configMethods  uint16
	apSetupLocked  bool
}



func (wps *WPSInfo) parseWPS(data []byte) {
	lenData := len(data)
	pos     := 0

	for pos + 4 <= lenData {
		t := binary.BigEndian.Uint16(data[pos : pos+2])
		l := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
	
		if pos + 4 + l > lenData { break }
		
		val := data[pos+4 : pos+4+l]
		
		switch t {
		// Version
		case 0x104A: if l >= 1 { wps.version = int(val[0]) }
		// WPS State
		case 0x1044: if l >= 1 { wps.state = int(val[0]) }
		// AP Setup Locked
		case 0x1057: if l >= 1 { wps.apSetupLocked = val[0] != 0 }
		// Config Methods
		case 0x1008, 0x1053:
			if l >= 2 { wps.configMethods = binary.BigEndian.Uint16(val) }
		}

		pos += 4 + l
	}
	
	if wps.version == 0 { wps.version = 0x10 }
}



func (wps *WPSInfo) getVersion() {
	if wps.version > 0 {
		wps.str = append(wps.str, fmt.Sprintf("%d.%d", wps.version >> 4, wps.version & 0x0F))
	}
}



func (wps *WPSInfo) getState() {
	if wps.state == 0 {
		wps.str = append(wps.str, "unconfigured")
		return
	}

	wps.str = append(wps.str, "configured")
}



func (wps *WPSInfo) getMethods() {
	methods   := wps.configMethods
	bitToName := []struct {
		bit  uint16
		name string
	}{
		{0x0001, "USB"},
		{0x0002, "ETHER"},
		{0x0004, "LAB"},
		{0x0008, "DISP"},
		{0x0010, "EXTNFC"},
		{0x0020, "INTNFC"},
		{0x0040, "NFCINTF"},
		{0x0080, "PBC"},
		{0x0100, "KPAD"},
	}

	for _, b := range bitToName {
		if methods&b.bit != 0 {
			wps.str = append(wps.str, b.name)
		}
	}
}



func (wps *WPSInfo) getLock() {
	if wps.apSetupLocked {
		wps.str = append(wps.str, "locked")
	}
}