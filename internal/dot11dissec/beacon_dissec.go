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
	"offscan/internal/models"
)



func (dd *Dot11Dissector) checkIfIsBeacon() bool {
	if len(dd.frame) < 24 {
		return false
	}

	fc := dd.frame[0]
	if ((fc>>2) & 0x03) == 0 && ((fc>>4) & 0x0F) == 8 {
		dd.IsBeacon = true
		return true
	}

	return false
}



func (dd *Dot11Dissector) GetTimestamp() string {
	if !dd.IsBeacon {
		return "unknown"
	}
	return formatUptime(dd.timestamp)
}



func formatUptime(tsf uint64) string {
	secs := tsf / 1_000_000

	days := secs / 86400
	secs %= 86400
	hours := secs / 3600

	if days > 0 {
		return fmt.Sprintf("%dd %02dh", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh", hours)
	}
	
	return "less than 1h"
}



func (dd *Dot11Dissector) GetBSSID() models.BSSID {
	var bssid models.BSSID
	if !dd.IsBeacon || len(dd.frame) < 24 {
		return bssid
	}
	copy(bssid[:], dd.frame[16:22])
	return bssid
}



func (dd *Dot11Dissector) GetSSID() models.SSID {
    var ssid models.SSID

    if !dd.IsBeacon {
        ssid.IsUnknown = true
        return ssid
    }

	data, ok := dd.ieCache[0x00]

    if !ok || len(data) <= 0 {
		ssid.IsHidden = true
    	return ssid
    }

	copyLen := len(data)
    if copyLen > 32 { copyLen = 32 }
	ssid.AddSSID(data)

    return ssid
}



func (dd *Dot11Dissector) GetChannel() uint8 {
	if !dd.IsBeacon { return 0 }
	
	if data, ok := dd.ieCache[0x03]; ok && len(data) >= 1 {
		return data[0]
	}
	
	return 0
}



func (dd *Dot11Dissector) GetSecurity() string {
	if !dd.IsBeacon { return "unknown" }
	
	if len(dd.frame) < 36 {
		return "OPEN"
	}
	
	capInfo := binary.LittleEndian.Uint16(dd.frame[34:36])

	// 1. WPA2 (RSN)
	if data, ok := dd.ieCache[0x30]; ok {
		sec := parseRSN(data)
		if sec != "" {
			return sec
		}
	}

	// 2. WPA1 (vendor specific)
	if dd.wpa1Data != nil {
		sec := parseWPA1(dd.wpa1Data)
		if sec != "" {
			return sec
		}
	}

	// 3. WEP
	if (capInfo & 0x0010) != 0 {
		return "WEP"
	}

	return "OPEN"
}



func parseRSN(data []byte) string {
	lenData := len(data)

	if lenData < 2 { return "" }
	
	ptr := 2
	ptr += 4
	
	if lenData < ptr + 2 { return "" }

	pairwiseCount := int(binary.LittleEndian.Uint16(data[ptr : ptr+2]))
	ptr    += 2
	cipher := ""
	
	if pairwiseCount > 0 && lenData >= ptr+4 {
		cipher  = decodeCipher(data[ptr : ptr+4])
		ptr    += pairwiseCount * 4
	}
	
	if lenData < ptr+2 { return "" }
	
	akmCount := int(binary.LittleEndian.Uint16(data[ptr : ptr+2]))
	ptr  += 2
	auth := ""
	
	if akmCount > 0 && lenData >= ptr+4 {
		auth = decodeAKM(data[ptr : ptr+4])
	}
	
	if auth   == "" { auth   = "PSK"  }
	if cipher == "" { cipher = "CCMP" }

	if auth == "SAE" || auth == "OWE" || auth == "FT-SAE" {
		return fmt.Sprintf("WPA3-%s-%s", auth, cipher)
	}

	return fmt.Sprintf("WPA2-%s-%s", auth, cipher)
}



func parseWPA1(data []byte) string {
	lenData := len(data)

	if lenData < 4 { return "" }

	version := binary.LittleEndian.Uint16(data[0:2])
	if version != 1 { return "" }

	ptr := 2 + 4 // group cipher
	
	if lenData < ptr + 2 { return "" }
	
	pairwiseCount := int(binary.LittleEndian.Uint16(data[ptr : ptr+2]))
	ptr    += 2
	cipher := ""
	
	if pairwiseCount > 0 && lenData >= ptr+4 {
		cipher = decodeCipher(data[ptr : ptr+4])
		ptr += pairwiseCount * 4
	}

	if lenData < ptr + 2 { return "" }

	akmCount := int(binary.LittleEndian.Uint16(data[ptr : ptr+2]))
	ptr      += 2
	auth     := ""
	
	if akmCount > 0 && lenData >= ptr+4 {
		auth = decodeAKM(data[ptr : ptr+4])
	}
	
	if auth   == "" { auth   = "PSK"  }
	if cipher == "" { cipher = "TKIP" }

	return fmt.Sprintf("WPA-%s-%s", auth, cipher)
}



func decodeCipher(suite []byte) string {
	if len(suite) < 4 || suite[0] != 0x00 || suite[1] != 0x0F || suite[2] != 0xAC {
		return ""
	}

	switch suite[3] {
	case 1  : return "WEP"
	case 2  : return "TKIP"
	case 4  : return "CCMP"
	case 5  : return "WEP104"
	case 6  : return "GCMP"
	case 8  : return "GCMP-256"
	case 9  : return "CCMP-256"
	default : return ""
	}
}



func decodeAKM(suite []byte) string {
	if len(suite) < 4 || suite[0] != 0x00 || suite[1] != 0x0F || suite[2] != 0xAC {
		return ""
	}
	switch suite[3] {
	case 1, 3, 5, 7, 11, 12, 13, 14, 15, 16, 17:
		return "MGT"
	case 2, 4, 6:
		return "PSK"
	case 8, 9:
		return "SAE"
	case 10:
		return "AP-PEER"
	case 18, 19:
		return "OWE"
	default:
		return ""
	}
}



func (dd *Dot11Dissector) GetStandard() string {
	if !dd.IsBeacon { return "unknown" }

	if data, ok := dd.ieCache[0xFF]; ok && len(data) > 0 && data[0] == 35 {
		return "802.11ax"
	}

	if _, ok := dd.ieCache[0xBF]; ok || dd.ieCache[0xC0] != nil {
		return "802.11ac"
	}

	if _, ok := dd.ieCache[0x2D]; ok || dd.ieCache[0x3D] != nil {
		return "802.11n"
	}

	return "802.11b/g"
}