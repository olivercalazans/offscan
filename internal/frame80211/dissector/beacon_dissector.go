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
	"net"
)



type BeaconDissector struct {
	pkt         []byte
	dot11Start  int
}



func NewBeaconDissector() *BeaconDissector {
	return &BeaconDissector{}
}



func (bd *BeaconDissector) UpdatePkt(rawPkt []byte) {
	bd.pkt        = rawPkt
	bd.dot11Start = 0

	if len(rawPkt) < 4 {
		return
	}

	if rawPkt[0] != 0x00 { return }
	
	rtLen := int(binary.LittleEndian.Uint16(rawPkt[2:4]))
	if rtLen > 0 && rtLen < len(rawPkt) {
		bd.dot11Start = rtLen
	}
}



func (bd *BeaconDissector) Dissec() ([]string, bool) {
	if len(bd.pkt)-bd.dot11Start < 24 {
		return nil, false
	}

	dot11        := bd.pkt[bd.dot11Start:]
	frameControl := dot11[0]
	fType        := (frameControl >> 2) & 0x03
	fSubtype     := (frameControl >> 4) & 0x0F

	if fType != 0 || fSubtype != 8 {
		return nil, false
	}

	bssid    := net.HardwareAddr(dot11[16:22]).String()
	ssid     := "<hidden>"
	channel  := "0"
	sec      := "Open"
	standard := "802.11b/g"

	if len(dot11) < 36 {
		return nil, false
	}

	capabilityInfo := binary.LittleEndian.Uint16(dot11[34:36])

	offset := 36
	for offset+2 <= len(dot11) {
		ieID  := dot11[offset]
		ieLen := int(dot11[offset+1])

		if offset+2+ieLen > len(dot11) {
			break
		}

		ieInfo := dot11[offset+2 : offset+2+ieLen]

		switch ieID {
		case 0: // SSID
			if len(ieInfo) > 0 {
				ssid = string(ieInfo)
			}

		case 3: // DS Parameter Set (Channel)
			if len(ieInfo) > 0 {
				channel = fmt.Sprintf("%d", ieInfo[0])
			}
		
		case 45: // HT Capabilities (802.11n)
			standard = "802.11n"
	
		case 61: // VHT Capabilities (802.11ac)
			standard = "802.11ac"
		
		case 255: // HE Capabilities (802.11ax / Wi-Fi 6)
			if len(ieInfo) > 0 && ieInfo[0] == 35 {
				standard = "802.11ax"
			}
		
		case 48: // RSN Info (WPA2/WPA3 Security)
			sec = parseRSNManual(ieInfo)
		}

		offset += 2 + ieLen
	}

	if sec == "Open" && (capabilityInfo&0x0010) != 0 {
		sec = "WEP"
	}

	return []string{ssid, bssid, channel, sec, standard}, true
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
		ptr   += 2

		if count > 0 && len(data) >= ptr+(count*4) {
			cipher  = decodeCipherManual(data[ptr : ptr+4])
			ptr    += (count * 4)
		}
	}

	var auth string
	if len(data) >= ptr+2 {
		count := int(binary.LittleEndian.Uint16(data[ptr : ptr+2]))
		ptr   += 2
		
		if count > 0 && len(data) >= ptr+4 {
			auth = decodeAKMManual(data[ptr : ptr+4])
		}
	}

	if auth == "SAE (WPA3)" { return "WPA3-" + cipher }
	if auth == "" { auth = "PSK" }

	return fmt.Sprintf("WPA2-%s-%s", auth, cipher)
}



func decodeCipherManual(suite []byte) string {
	if suite[0] != 0x00 || suite[1] != 0x0F || suite[2] != 0xAC {
		return "Unknown"
	}

	switch suite[3] {
	case 2:  return "TKIP"
	case 4:  return "CCMP(AES)"
	case 5:  return "WEP"
	case 6:  return "GCMP"
	default: return "Reserved"
	}
}



func decodeAKMManual(suite []byte) string {
	if suite[0] != 0x00 || suite[1] != 0x0F || suite[2] != 0xAC {
		return "Unknown"
	}

	switch suite[3] {
	case 1:  return "802.1x"
	case 2:  return "PSK"
	case 8:  return "SAE (WPA3)"
	case 6:  return "PSK-SHA256"
	default: return "Reserved"
	}
}