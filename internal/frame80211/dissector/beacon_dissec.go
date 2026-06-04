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

package dissector

import (
	"encoding/binary"
	"fmt"
)



func (dd *Dot11Dissector) checkIfIsBeacon() bool {
	if len(dd.frame) < 24 { return false }

	frameControl := dd.frame[0] 
	fType        := (frameControl >> 2) & 0x03
	fSubtype     := (frameControl >> 4) & 0x0F

	if fType != 0 || fSubtype != 8 {
		return false
	}

	dd.IsBeacon = true
	return true
}



func (dd *Dot11Dissector) GetSSID() string {
	if !dd.IsBeacon {
		return "unknown"
	}

	offset := 36
	for offset+2 <= len(dd.frame) {
		ieID  := dd.frame[offset]
		ieLen := int(dd.frame[offset+1])
		
		if offset+2+ieLen > len(dd.frame) {
			break
		}
		
		if ieID == 0 { // SSID
			ieInfo := dd.frame[offset+2 : offset+2+ieLen]
			if len(ieInfo) > 0 {
				return string(ieInfo)
			}
		
			return "<hidden>"
		}
		
		offset += 2 + ieLen
	}
	
	return "<hidden>"
}



func (dd *Dot11Dissector) GetBSSID() [6]byte {
	var bssid [6]byte

	if !dd.IsBeacon || len(dd.frame) < 24 {
		return bssid
	}
	
	copy(bssid[:], dd.frame[16:22])	
	return bssid
}




func (dd *Dot11Dissector) GetChannel() uint8 {
	if !dd.IsBeacon {
		return 0
	}

	offset  := 36
	for offset+2 <= len(dd.frame) {
		ieID  := dd.frame[offset]
		ieLen := int(dd.frame[offset+1])
		
		if offset+2+ieLen > len(dd.frame) {
			break
		}
		
		if ieID == 3 { // DS Parameter Set
			ieInfo := dd.frame[offset+2 : offset+2+ieLen]
			if len(ieInfo) > 0 {
				return ieInfo[0]
			}
		}

		offset += 2 + ieLen
	}

	return 0
}



func (dd *Dot11Dissector) GetSecurity() string {
	if !dd.IsBeacon {
		return "unknown"
	}

	if len(dd.frame) < 36 {
		return "Open"
	}

	capabilityInfo := binary.LittleEndian.Uint16(dd.frame[34:36])
	security       := "Open"

	offset := 36
	for offset+2 <= len(dd.frame) {
		ieID  := dd.frame[offset]
		ieLen := int(dd.frame[offset+1])
		
		if offset+2+ieLen > len(dd.frame) {
			break
		}

		if ieID == 48 { // RSN Info
			ieInfo   := dd.frame[offset+2 : offset+2+ieLen]
			security  = parseRSNManual(ieInfo)
			break
		}

		offset += 2 + ieLen
	}

	if security == "Open" && (capabilityInfo&0x0010) != 0 {
		security = "WEP"
	}
	
	return security
}



func parseRSNManual(data []byte) string {
	if len(data) < 2 {
		return "WPA2"
	}

	ptr := 2

	var cipher string
	if len(data) >= ptr+4 {
		cipher = decodeCipherManual(data[ptr : ptr+4])
		ptr += 4
	}

	if len(data) >= ptr+2 {
		count := int(binary.LittleEndian.Uint16(data[ptr : ptr+2]))
		ptr += 2

		if count > 0 && len(data) >= ptr+(count*4) {
			cipher = decodeCipherManual(data[ptr : ptr+4])
			ptr += (count * 4)
		}
	}

	var auth string
	if len(data) >= ptr+2 {
		count := int(binary.LittleEndian.Uint16(data[ptr : ptr+2]))
		ptr += 2

		if count > 0 && len(data) >= ptr+4 {
			auth = decodeAKMManual(data[ptr : ptr+4])
		}
	}

	if auth == "SAE (WPA3)" {
		return "WPA3-" + cipher
	}
	if auth == "" {
		auth = "PSK"
	}

	return fmt.Sprintf("WPA2-%s-%s", auth, cipher)
}



func (dd *Dot11Dissector) GetStandard() string {
	if !dd.IsBeacon {
		return "unknown"
	}

	standard := "802.11b/g"
	offset   := 36
	
	for offset+2 <= len(dd.frame) {
		ieID  := dd.frame[offset]
		ieLen := int(dd.frame[offset+1])
		
		if offset+2+ieLen > len(dd.frame) {
			break
		}
		
		switch ieID {
		case 45:
			standard = "802.11n"
		case 61:
			standard = "802.11ac"
		case 255:
			ieInfo := dd.frame[offset+2 : offset+2+ieLen]
			if len(ieInfo) > 0 && ieInfo[0] == 35 {
				standard = "802.11ax"
			}
		}

		offset += 2 + ieLen
	}

	return standard
}



func decodeCipherManual(suite []byte) string {
	if suite[0] != 0x00 || suite[1] != 0x0F || suite[2] != 0xAC {
		return "Unknown"
	}

	switch suite[3] {
	case 2  : return "TKIP"
	case 4  : return "CCMP(AES)"
	case 5  : return "WEP"
	case 6  : return "GCMP"
	default : return "Reserved"
	}
}



func decodeAKMManual(suite []byte) string {
	if suite[0] != 0x00 || suite[1] != 0x0F || suite[2] != 0xAC {
		return "Unknown"
	}

	switch suite[3] {
	case 1  : return "802.1x"
	case 2  : return "PSK"
	case 8  : return "SAE (WPA3)"
	case 6  : return "PSK-SHA256"
	default : return "Reserved"
	}
}