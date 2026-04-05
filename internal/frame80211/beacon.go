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

package frame80211

import (
	"encoding/binary"
	"fmt"
	"net"
	"offscan/internal/utils"
	"time"
)



type Beacon struct {
    buffer [119]byte
    length int
}



func NewBeacon() *Beacon {
    b := &Beacon{}
    MinimalRariotapHeader(b.buffer[:12])

    b.buffer[12] = 0x80
    b.buffer[13] = 0x00
    b.buffer[14] = 0x00
    b.buffer[15] = 0x00

    copy(b.buffer[16:22], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
    binary.LittleEndian.PutUint16(b.buffer[44:46], 100)

    return b
}



func (b *Beacon) Beacon(bssid net.HardwareAddr, ssid string, seq uint16, channel uint8, sec string) []byte {
    b.beaconHeader(bssid, seq)
    b.beaconBody(ssid, channel, sec)
    return b.buffer[:b.length]
}



func (b *Beacon) beaconHeader(bssid net.HardwareAddr, seq uint16) {
    copy(b.buffer[22:28], bssid[:])
    copy(b.buffer[28:34], bssid[:])

    seqCtrl := (seq & 0x0FFF) << 4
    binary.LittleEndian.PutUint16(b.buffer[34:36], seqCtrl)
}



func (b *Beacon) beaconBody(ssid string, channel uint8, sec string) {
    ts := uint64(time.Now().UnixMicro())
    binary.LittleEndian.PutUint64(b.buffer[36:44], ts)

    secFlags, secData := getSecData(sec)
    copy(b.buffer[46:48], secFlags[:])

    ssidBytes := []byte(ssid)
    ssidLen   := len(ssidBytes)
    
    if ssidLen > 32 {
        ssidLen = 32
    }
    idx := 48

    b.buffer[idx]   = 0x00
    b.buffer[idx+1] = byte(ssidLen)
    idx += 2
    copy(b.buffer[idx:idx+ssidLen], ssidBytes[:ssidLen])
    idx += ssidLen

    b.buffer[idx]   = 0x01
    b.buffer[idx+1] = 0x08
    copy(b.buffer[idx+2:idx+10], []byte{
        0x82, 0x84, 0x8B, 0x96, // 1, 2, 5.5, 11 Mbps
        0x0C, 0x12, 0x18, 0x24, // 6, 9, 12, 24 Mbps
    })
    idx += 10

    b.buffer[idx]   = 0x03
    b.buffer[idx+1] = 0x01
    b.buffer[idx+2] = channel
    idx += 3

    b.buffer[idx]   = 0x05
    b.buffer[idx+1] = 0x04
    copy(b.buffer[idx+2:idx+6], []byte{0x00, 0x01, 0x00, 0x00})
    idx += 6

    if len(secData) > 0 {
        copy(b.buffer[idx:idx+len(secData)], secData)
        idx += len(secData)
    }

    b.buffer[idx]   = 0x32
    b.buffer[idx+1] = 0x04
    copy(b.buffer[idx+2:idx+6], []byte{0x30, 0x48, 0x60, 0x6C})
    idx += 6

    b.length = idx
}



func getSecData(sec string) ([2]byte, []byte) {
    switch sec {
    case "open":
        return [2]byte{0x01, 0x04}, nil
    case "wpa":
        return [2]byte{0x11, 0x04}, []byte{
            // Vendor Specific IE (ID 221) para WPA
            0xDD, 0x16,
            0x00, 0x50, 0xF2,
            0x01, 0x01, 0x00, 0x00, 0x50, 0xF2, 0x02,
            0x01, 0x00, 0x00, 0x50, 0xF2, 0x04,
            0x01, 0x00, 0x00, 0x50, 0xF2, 0x02,
            0x00, 0x00,
        }
    case "wpa2":
        return [2]byte{0x11, 0x04}, []byte{
            // RSN IE (ID 48) para WPA2
            0x30, 0x14,
            0x01, 0x00,
            0x00, 0x0F, 0xAC, 0x04,
            0x01, 0x00,
            0x00, 0x0F, 0xAC, 0x04,
            0x01, 0x00,
            0x00, 0x0F, 0xAC, 0x02,
            0x00, 0x00,
        }
    case "wpa3":
        return [2]byte{0x11, 0x04}, []byte{
            // RSN IE (ID 48) para WPA3
            0x30, 0x18,
            0x02, 0x00,
            0x00, 0x0F, 0xAC, 0x0C,
            0x01, 0x00,
            0x00, 0x0F, 0xAC, 0x0C,
            0x01, 0x00,
            0x00, 0x0F, 0xAC, 0x06,
            0x00, 0x00,
            0x00, 0x0F, 0xAC, 0x08,
        }
    default:
        utils.Abort(fmt.Sprintf("Unknown security flag: %s", sec))
        return [2]byte{}, nil
    }
}