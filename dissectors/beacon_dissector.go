package dissectors

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf8"
)



type BeaconDissector struct {
    frame []byte
}



func NewBeaconDissector() *BeaconDissector {
    return &BeaconDissector{}
}



func (bd *BeaconDissector) DissecBeacon(beacon []byte) ([]string, bool) {
    bd.frame = beacon

    offset   := bd.findFrameOffset()
    bd.frame  = beacon[offset:]
    
	if len(bd.frame) < 24 {
        return nil, false
    }
    
	frameCtrl    := binary.LittleEndian.Uint16(bd.frame[0:2])
    frameType    := (frameCtrl >> 2) & 0x03
    frameSubtype := (frameCtrl >> 4) & 0x0F
    
	if frameType != 0 || frameSubtype != 8 {
        return nil, false
    }
    
	bssid   := bd.getBSSID()
    ssid    := bd.getSSID()
    channel := bd.getChannel()
    sec     := bd.getSecType()
    
	return []string{ssid, bssid, channel, sec}, true
}



func (bd *BeaconDissector) findFrameOffset() int {
    if offset, ok := bd.findFrameStartByType(); ok {
        return offset
    }

	if offset, ok := bd.skipRadiotapHeader(); ok {
        return offset
    }

	if offset, ok := bd.skipCommonHeaders(); ok {
        return offset
    }

	return 0
}



func (bd *BeaconDissector) findFrameStartByType() (int, bool) {
    for i := 0; i+24 <= len(bd.frame); i++ {

		if i+2 > len(bd.frame) {
            continue
        }

		frameCtrl    := binary.LittleEndian.Uint16(bd.frame[i : i+2])
        frameType    := (frameCtrl >> 2) & 0x03
        frameSubtype := (frameCtrl >> 4) & 0x0F

		if frameType != 0 || frameSubtype != 8 {
            continue
        }

		if i+4 > len(bd.frame) {
            continue
        }
        
		duration := binary.LittleEndian.Uint16(bd.frame[i+2 : i+4])
        if duration > 0x3AFF {
            continue
		}
    
		return i, true
    }
    
	return 0, false
}



func (bd *BeaconDissector) skipRadiotapHeader() (int, bool) {
    if len(bd.frame) < 8 || bd.frame[0] != 0x00 || bd.frame[1] != 0x00 {
        return 0, false
    }

	radiotapLen := int(binary.LittleEndian.Uint16(bd.frame[2:4]))
    if radiotapLen < 8 || radiotapLen+24 > len(bd.frame) {
        return 0, false
    }

	afterRadiotap := bd.frame[radiotapLen:]
    if len(afterRadiotap) < 24 {
        return 0, false
    }

	frameCtrl := binary.LittleEndian.Uint16(afterRadiotap[0:2])
    frameType := (frameCtrl >> 2) & 0x03

	if frameType > 2 {
        return 0, false
    }

	return radiotapLen, true
}



func (bd *BeaconDissector) skipCommonHeaders() (int, bool) {
    commonOffsets := []int{0, 4, 8, 12, 16, 24, 32, 36}
    
	for _, offset := range commonOffsets {
        if offset+24 > len(bd.frame) {
            continue
        }

		frame        := bd.frame[offset:]
        frameCtrl    := binary.LittleEndian.Uint16(frame[0:2])
        frameType    := (frameCtrl >> 2) & 0x03
        frameSubtype := (frameCtrl >> 4) & 0x0F
 
		if frameType == 0 && frameSubtype == 8 {
            return offset, true
        }
    }
    
	return 0, false
}



func (bd *BeaconDissector) getBSSID() string {
    if len(bd.frame) < 22 {
        return "00:00:00:00:00:00"
    }

	b := bd.frame[16:22]
    return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}



func (bd *BeaconDissector) getSSID() string {
    const hidden = "<hidden>"

	if len(bd.frame) < 38 {
        return hidden
    }

	offset := 36
    for offset+1 < len(bd.frame) {
        elementID  := bd.frame[offset]
        elementLen := int(bd.frame[offset+1])
        offset += 2
        
		if elementID != 0 || elementLen <= 0 {
            offset += elementLen
            continue
        }
        
		if offset+elementLen > len(bd.frame) {
            offset += elementLen
            continue
        }

		ssidBytes := bd.frame[offset : offset+elementLen]
        allZero   := true

		for _, b := range ssidBytes {
            if b != 0 {
                allZero = false
                break
            }
        }
        
		if allZero {
            return hidden
        }

		if utf8.Valid(ssidBytes) {
            ssid := string(ssidBytes)
            if strings.TrimSpace(ssid) != "" {
                return ssid
            }
        }

		return formatSSIDBytes(ssidBytes)
    }

	return hidden
}



func formatSSIDBytes(ssid []byte) string {
    isPrintable := true

	for _, b := range ssid {
        if b < 32 || b > 126 {
            isPrintable = false
            break
        }
    }

	if isPrintable {
        return string(ssid)
    }

	displayLen := 8
    if len(ssid) < displayLen {
        displayLen = len(ssid)
    }

	hexPart := ""
    for i := 0; i < displayLen; i++ {
        hexPart += fmt.Sprintf("%02X", ssid[i])
    }

	if len(ssid) > displayLen {
        return hexPart + "..."
    }

	return hexPart
}



func (bd *BeaconDissector) getChannel() string {
    if len(bd.frame) < 38 {
        return "0"
    }

	offset := 36
    for offset+1 < len(bd.frame) {
        elementID  := bd.frame[offset]
        elementLen := int(bd.frame[offset+1])
        offset += 2
        
		if elementID == 3 && elementLen == 1 && offset < len(bd.frame) {
            return fmt.Sprintf("%d", bd.frame[offset])
        }
        
		offset += elementLen
    }
    
	return "0"
}



func (bd *BeaconDissector) getSecType() string {
    if len(bd.frame) < 38 {
        return "????"
    }

	flags  := &secFlags{isOpen: true}
    offset := 36

	for offset+1 < len(bd.frame) {
        elementID  := bd.frame[offset]
        elementLen := int(bd.frame[offset+1])
        
		if offset+2+elementLen > len(bd.frame) {
            break
        }
        
		elementData := bd.frame[offset+2 : offset+2+elementLen]
        
		switch elementID {
        case 0x30: processRSNElement(elementData, flags)
        case 0xDD: processVendorElement(elementData, flags)
        case 0x06: processPrivacyElement(elementData, flags)
        }
        
		offset += 2 + elementLen
    }
    
	return flags.String()
}



type secFlags struct {
	hasRSN  bool
	hasWPA  bool
	hasWEP  bool
	isOpen  bool
	isWPA3  bool
}



func processRSNElement(data []byte, flags *secFlags) {
	flags.hasRSN = true
	flags.isOpen = false

	if len(data) >= 20 {
		flags.isWPA3 = checkForWPA3(data)
	}
}



func checkForWPA3(rsnData []byte) bool {
	offset := 6

	if offset+2 > len(rsnData) {
		return false
	}
	
	pairwiseCount := int(binary.LittleEndian.Uint16(rsnData[offset : offset+2]))
	offset += 2 + pairwiseCount*4
	
	if offset+2 > len(rsnData) {
		return false
	}
	
	akmCount := int(binary.LittleEndian.Uint16(rsnData[offset : offset+2]))
	offset += 2
	
	for i := 0; i < akmCount; i++ {
		if offset+4 > len(rsnData) {
			break
		}

		if rsnData[offset] == 0x00 && rsnData[offset+1] == 0x0F && rsnData[offset+2] == 0xAC {
			suiteType := rsnData[offset+3]
			if suiteType == 8 || suiteType == 9 {
				return true
			}
		}

		offset += 4
	}

	return false
}



func processVendorElement(data []byte, flags *secFlags) {
	if len(data) >= 4 && data[0] == 0x00 && data[1] == 0x50 && data[2] == 0xF2 && data[3] == 0x01 {
		flags.hasWPA = true
		flags.isOpen = false
	}
}



func processPrivacyElement(data []byte, flags *secFlags) {
	if len(data) > 0 && (data[0]&0x10) != 0 {
		flags.hasWEP = true
		flags.isOpen = false
	}
}



func (f *secFlags) String() string {
	switch {
	case f.isWPA3: return "WPA3"
	case f.hasRSN: return "WPA2"
	case f.hasWPA: return "WPA"
	case f.hasWEP: return "WEP"
	case f.isOpen: return "Open"
	default:       return "Unknown"
	}
}