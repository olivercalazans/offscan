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
	
	dd.wpsInfo.reset()
	dd.wpsInfo.parseWPS(dd.wpsData)
	dd.wpsInfo.getVersion()
	dd.wpsInfo.getState()
	dd.wpsInfo.getMethods()
	dd.wpsInfo.getLock()

	return strings.Join(dd.wpsInfo.str, " ")
}



type WPSInfo struct {
	str            []string
	version        int
	state          int 
	configMethods  uint16
	apSetupLocked  bool
}



func (wps *WPSInfo) reset() {
	clear(wps.str)
	wps.str = wps.str[:0]

	wps.version       = 0
	wps.state         = 0
	wps.configMethods = 0
	wps.apSetupLocked = false
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
	m := wps.configMethods

	if m & 0x0001 != 0 { wps.str = append(wps.str, "USB")     }
	if m & 0x0002 != 0 { wps.str = append(wps.str, "ETHER")   }
	if m & 0x0004 != 0 { wps.str = append(wps.str, "LAB")     }
	if m & 0x0008 != 0 { wps.str = append(wps.str, "DISP")    }
	if m & 0x0010 != 0 { wps.str = append(wps.str, "EXTNFC")  }
	if m & 0x0020 != 0 { wps.str = append(wps.str, "INTNFC")  }
	if m & 0x0040 != 0 { wps.str = append(wps.str, "NFCINTF") }
	if m & 0x0080 != 0 { wps.str = append(wps.str, "PBC")     }
	if m & 0x0100 != 0 { wps.str = append(wps.str, "KPAD")    }
}



func (wps *WPSInfo) getLock() {
	if wps.apSetupLocked {
		wps.str = append(wps.str, "locked")
	}
}
