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
	"fmt"
	"net"
	"offscan/internal/utils"
	"time"
)



type Beacon struct {
    buffer     [150]byte
    offset     int
    secOffset  int
}



func NewBeacon() Beacon {
    b := Beacon{}
    b.buildFixed()
    return b
}



func (b *Beacon) buildFixed() {
    minimalRariotapHeader(b.buffer[:12])
    b.setFramCtrl()
    b.setDuration()
    b.setDstAddr()
    b.setInterval()
}



func (b *Beacon) setFramCtrl() {
    b.buffer[12] = 0x80
    b.buffer[13] = 0x00
}



func (b *Beacon) setDuration() {
    b.buffer[14] = 0x00
    b.buffer[15] = 0x00
}



func (b *Beacon) setDstAddr() {
    broadcast := [6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
    copy(b.buffer[16:22], broadcast[:])
}



func (b *Beacon) SetSrcAddr(mac net.HardwareAddr) {
    copy(b.buffer[22:28], mac[:])
}



func (b *Beacon) SetBSSID(bssid net.HardwareAddr) {
    copy(b.buffer[28:34], bssid[:])
}



func (b *Beacon) SetSeqCtrl(seq uint16) {
    seqCtrl := (seq & 0x0FFF) << 4
    binary.LittleEndian.PutUint16(b.buffer[34:36], seqCtrl)
}



func (b *Beacon) setTimestamp() {
    ts := uint64(time.Now().UnixMicro())
    binary.LittleEndian.PutUint64(b.buffer[36:44], ts)
}



func (b *Beacon) setInterval() {
    binary.LittleEndian.PutUint16(b.buffer[44:46], 100)
}



func (b *Beacon) setCapInfo(secFlags [2]byte) {
    copy(b.buffer[46:48], secFlags[:])
}



func (b *Beacon) setSSID(ssid string) {
    ssidLen  := len(ssid)
    b.offset  = 48

    b.buffer[b.offset] = 0x00
    b.offset += 1

    b.buffer[b.offset] = byte(ssidLen)
    b.offset += 1
    
    copy(b.buffer[b.offset : b.offset + ssidLen], ssid)
    b.offset += ssidLen
}



func (b *Beacon) setRates() {
    b.buffer[b.offset] = 0x01
    b.offset += 1

    b.buffer[b.offset] = 0x08
    b.offset += 1

    rates := [8]byte{
        0x82, 0x84, 0x8B, 0x96, // 1, 2, 5.5, 11 Mbps
        0x0C, 0x12, 0x18, 0x24, // 6, 9, 12, 24 Mbps
    }
    
    copy(b.buffer[b.offset : b.offset + 8], rates[:])
    b.offset += 8
}



func (b *Beacon) setChnl(chnl uint8) {
    b.buffer[b.offset] = 0x03
    b.offset += 1

    b.buffer[b.offset] = 0x01
    b.offset += 1

    b.buffer[b.offset] = chnl
    b.offset += 1
}



func (b *Beacon) setTIM() {
    b.buffer[b.offset] = 0x05
    b.offset += 1
    
    b.buffer[b.offset] = 0x04
    b.offset += 1

    tim := [4]byte{0x00, 0x01, 0x00, 0x00}
    copy(b.buffer[b.offset : b.offset + 4], tim[:])
    b.offset += 4
}



func (b *Beacon) SetSec(sec string) {
    b.offset = b.secOffset

    secFlags, secBytes, lenDataSec := getSecData(sec)
    b.setCapInfo(secFlags)

    if lenDataSec <= 0 { return }

    secData := secBytes[:lenDataSec]
    copy(b.buffer[b.offset : b.offset + lenDataSec], secData)
    b.offset += lenDataSec

    b.setExtSuppRates()
}



func (b *Beacon) setExtSuppRates() {
    b.buffer[b.offset] = 0x32
    b.offset += 1

    b.buffer[b.offset] = 0x04
    b.offset += 1

    extRates := [4]byte{0x30, 0x48, 0x60, 0x6C}
    copy(b.buffer[b.offset : b.offset + 4], extRates[:])
    b.offset += 4
}



func (b *Beacon) SetBodyInfo(ssid string, chnl uint8) {
    b.setSSID(ssid)
    b.setRates()
    b.setChnl(chnl)
    b.setTIM()
    b.secOffset = b.offset
}



func (b *Beacon) Beacon() []byte {
    b.setTimestamp() 
    return b.buffer[:b.offset]
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
        utils.Abort(fmt.Sprintf("Unknown security flag: %s", sec))
        return [2]byte{}, [30]byte{}, 0
    }
}
