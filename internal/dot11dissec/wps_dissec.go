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
	"bytes"
	"encoding/binary"
	"offscan/internal/models"
)



func (dd *Dot11Dissector) GetWPS() models.WPSInfo {
	if len(dd.wpsData) == 0 {
		return models.WPSInfo{}
	}

	wps := dd.parseWPS()
	return wps
}



func (dd *Dot11Dissector) parseWPS() models.WPSInfo {
	var info models.WPSInfo

	lenData := len(dd.wpsData)
	pos     := 0

	for pos+4 <= lenData {
		t := binary.BigEndian.Uint16(dd.wpsData[pos : pos+2])
		l := int(binary.BigEndian.Uint16(dd.wpsData[pos+2 : pos+4]))

		if pos + 4 + l > lenData { break }

		val := dd.wpsData[pos+4 : pos+4+l]

		switch t {
		case attrVersion: 
    		if l >= 1 && info.Version() == 0 {
    		    info.SetVersion(val[0])
    		}

		case attrWPSState: 
			if l >= 1 { 
				info.SetConfig(val[0] == 2)
				info.SetStatePresence()
			}
		
		case attrAPSetupLocked: 
			if l >= 1 { 
				info.SetAPSetupLock(val[0] != 0)
			}
		
		case attrSelectedRegistrar:
		    if l >= 1 {
		        info.SetRegistrar(val[0] != 0)
		    }

		case attrVendorExtension:
			if v := checkVendorExt(l, val); v != 0 {
    		    info.SetVersion(v)
    		}
		}

		pos += 4 + l
	}

	return info
}



func checkVendorExt(l int, val []byte) uint8 {
	if l < 3 || !bytes.Equal(val[:3], []byte{0x00, 0x37, 0x2A}) {
        return 0
    }

	subpos := 3
    for subpos+2 <= l {
        subType := val[subpos]
        subLen  := int(val[subpos+1])

        if subpos+2+subLen > l { return 0 }
        
		if subType == 0x00 && subLen >= 1 {
            return val[subpos+2]
        }
        
		subpos += 2 + subLen
    }

	return 0
}