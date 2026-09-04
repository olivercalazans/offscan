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



func (dd *Dot11Dissector) GetTimestamp() models.Uptime {
	var uptime models.Uptime

	if !dd.IsBeacon {
		return uptime
	}
	
	secs  := dd.timestamp / 1_000_000
    days  := uint16(secs / 86400)
    secs  %= 86400
    hours := uint8(secs / 3600)

    if days == 0 && hours == 0 {
        return models.Uptime{Days: 0, Hours: 255}
    }

	return models.Uptime{Days: days, Hours: hours}
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

    if len(dd.ssidData) == 0 {
        ssid.IsHidden = true
        return ssid
    }

    ssid.AddSSID(dd.ssidData)
    return ssid
}



func (dd *Dot11Dissector) GetChannel() uint8 {
    if !dd.IsBeacon {
        return 0
    }

    if len(dd.dsParam) > 0 {
        return dd.dsParam[0]
    }

    return 0
}



func (dd *Dot11Dissector) GetSecurity() models.WifiSec {
	var sec models.WifiSec

	if !dd.IsBeacon {
		return sec
	}

	if len(dd.frame) < 36 {
		sec.Type = models.SecTypeOpen
		return sec
	}

	capInfo := binary.LittleEndian.Uint16(dd.frame[34:36])

	if len(dd.rsn) > 0 {
		sec = parseRSN(dd.rsn)
		if sec.Type != models.SecTypeNone {
			return sec
		}
	}

	if len(dd.wpa1Data) > 0 {
		sec = parseWPA1(dd.wpa1Data)
		if sec.Type != models.SecTypeNone {
			return sec
		}
	}

	if (capInfo & 0x0010) != 0 {
		sec.Type = models.SecTypeWEP
		return sec
	}

	sec.Type = models.SecTypeOpen
	return sec
}



func parseRSN(data []byte) models.WifiSec {
	var sec models.WifiSec
	sec.Type    = models.SecTypeWPA
	sec.Version = 2

	lenData := len(data)
	if lenData < 2 {
		return sec
	}

	ptr := 2
	ptr += 4 // group cipher

	if lenData < ptr+2 {
		return sec
	}

	pairwiseCount := int(binary.LittleEndian.Uint16(data[ptr : ptr+2]))
	ptr += 2

	if pairwiseCount > 0 && lenData >= ptr+4 {
		sec.Cipher = decodeCipher(data[ptr : ptr+4])
		ptr += pairwiseCount * 4
	}

	if lenData < ptr+2 {
		return sec
	}

	akmCount := int(binary.LittleEndian.Uint16(data[ptr : ptr+2]))
	ptr += 2

	if akmCount > 0 && lenData >= ptr+4 {
		sec.Auth = decodeAKM(data[ptr : ptr+4])
	}

	return sec
}



func parseWPA1(data []byte) models.WifiSec {
	var sec models.WifiSec
	sec.Type    = models.SecTypeWPA
	sec.Version = 1

	lenData := len(data)
	if lenData < 4 {
		return sec
	}

	version := binary.LittleEndian.Uint16(data[0:2])
	if version != 1 {
		return sec
	}

	ptr := 2 + 4 // group cipher

	if lenData < ptr+2 {
		return sec
	}

	pairwiseCount := int(binary.LittleEndian.Uint16(data[ptr : ptr+2]))
	ptr += 2

	if pairwiseCount > 0 && lenData >= ptr+4 {
		sec.Cipher = decodeCipher(data[ptr : ptr+4])
		ptr += pairwiseCount * 4
	}

	if lenData < ptr+2 {
		return sec
	}

	akmCount := int(binary.LittleEndian.Uint16(data[ptr : ptr+2]))
	ptr += 2

	if akmCount > 0 && lenData >= ptr+4 {
		sec.Auth = decodeAKM(data[ptr : ptr+4])
	}

	return sec
}



func decodeCipher(suite []byte) models.SecurityCipher {
	if len(suite) < 4 || suite[0] != 0x00 || suite[1] != 0x0F || suite[2] != 0xAC {
		return models.CipherNone
	}

	switch suite[3] {
	case 1:  return models.CipherWEP
	case 2:  return models.CipherTKIP
	case 4:  return models.CipherCCMP
	case 5:  return models.CipherWEP104
	case 6:  return models.CipherGCMP
	case 8:  return models.CipherGCMP256
	case 9:  return models.CipherCCMP256
	default: return models.CipherNone
	}
}



func decodeAKM(suite []byte) models.SecurityAuth {
	if len(suite) < 4 || suite[0] != 0x00 || suite[1] != 0x0F || suite[2] != 0xAC {
		return models.AuthNone
	}
	switch suite[3] {
	case 1, 3, 5, 7, 11, 12, 13, 14, 15, 16, 17:
		return models.AuthMGT

	case 2, 4, 6: return models.AuthPSK
	case 8, 9:    return models.AuthSAE
	case 10:      return models.AuthAPPeer
	case 18, 19:  return models.AuthOWE
	default:      return models.AuthNone
	}
}



func (dd *Dot11Dissector) GetStandard() models.WifiStd {
    if !dd.IsBeacon {
		return models.StdUnknown
	}

    if len(dd.heCap) > 0 && dd.heCap[0] == 35 {
        return models.StdAX
    }

    if len(dd.vhtCap) > 0 {
        return models.StdAC
    }

    if len(dd.htCap) > 0 {
        return models.StdN
    }

    return models.StdB_G
}