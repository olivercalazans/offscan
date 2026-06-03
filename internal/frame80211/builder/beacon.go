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

package builder

import (
	"encoding/binary"
	"net"
	"offscan/internal/utils"
	"time"
)



type Beacon struct {
    buffer [150]byte
    length int
}



func NewBeacon() Beacon {
    b := Beacon{}
    b.buildBeaconFixed()
    return b
}



func (b *Beacon) buildBeaconFixed() {
    minimalRariotapHeader(b.buffer[:12])

    b.buffer[12] = 0x80
    b.buffer[13] = 0x00
    b.buffer[14] = 0x00
    b.buffer[15] = 0x00

    broadcast := [6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
    copy(b.buffer[16:22], broadcast[:])
    binary.LittleEndian.PutUint16(b.buffer[44:46], 100)

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

    secFlags, secBytes, lenDataSec := getSecData(sec)
    secData := secBytes[:lenDataSec]

    copy(b.buffer[46:48], secFlags[:])

    ssidLen   := len(ssid)
    
    if ssidLen > 32 {
        ssidLen = 32
    }
    idx := 48

    b.buffer[idx]   = 0x00
    b.buffer[idx+1] = byte(ssidLen)
    idx += 2
    copy(b.buffer[idx:idx+ssidLen], ssid)
    idx += ssidLen

    b.buffer[idx]   = 0x01
    b.buffer[idx+1] = 0x08

    rates := [8]byte{
        0x82, 0x84, 0x8B, 0x96, // 1, 2, 5.5, 11 Mbps
        0x0C, 0x12, 0x18, 0x24, // 6, 9, 12, 24 Mbps
    }
    copy(b.buffer[idx+2:idx+10], rates[:])
    idx += 10

    b.buffer[idx]   = 0x03
    b.buffer[idx+1] = 0x01
    b.buffer[idx+2] = channel
    idx += 3

    b.buffer[idx]   = 0x05
    b.buffer[idx+1] = 0x04

    tim := [4]byte{0x00, 0x01, 0x00, 0x00}
    copy(b.buffer[idx+2:idx+6], tim[:])
    idx += 6

    if len(secData) > 0 {
        copy(b.buffer[idx:idx+len(secData)], secData)
        idx += len(secData)
    }

    b.buffer[idx]   = 0x32
    b.buffer[idx+1] = 0x04

    extRates := [4]byte{0x30, 0x48, 0x60, 0x6C}
    copy(b.buffer[idx+2:idx+6], extRates[:])
    idx += 6

    b.length = idx
}



func getSecData(sec string) ([2]byte, [30]byte, int) {
    switch sec {
    case "open":
        return [2]byte{0x01, 0x04}, [30]byte{}, 0

    case "wpa":
        wpa := [30]byte{
            0xDD, 0x16, 0x00, 0x50, 0xF2, 0x01, 0x01, 0x00, 
            0x00, 0x50, 0xF2, 0x02, 0x01, 0x00, 0x00, 0x50, 
            0xF2, 0x04, 0x01, 0x00, 0x00, 0x50, 0xF2, 0x02, 
            0x00, 0x00,
        }
        return [2]byte{0x11, 0x04}, wpa, 26

    case "wpa2":
        wpa2 := [30]byte{
            0x30, 0x14, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 
            0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 
            0x00, 0x0F, 0xAC, 0x02, 0x00, 0x00,
        }
        return [2]byte{0x11, 0x04}, wpa2, 22

    case "wpa3":
        wpa3 := [30]byte{
            0x30, 0x18, 0x02, 0x00, 0x00, 0x0F, 0xAC, 0x0C, 
            0x01, 0x00, 0x00, 0x0F, 0xAC, 0x0C, 0x01, 0x00, 
            0x00, 0x0F, 0xAC, 0x06, 0x00, 0x00, 0x00, 0x0F, 
            0xAC, 0x08,
        }
        return [2]byte{0x11, 0x04}, wpa3, 26

    default:
        utils.Abort("Unknown security flag: " + sec)
        return [2]byte{}, [30]byte{}, 0
    }
}
