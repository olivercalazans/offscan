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

package models


const (
    ssidLenMask     uint8 = 0x3F // 0011 1111
    ssidHiddenMask  uint8 = 0x40 // 0100 0000
    ssidUnknownMask uint8 = 0x80 // 1000 0000
)


// alignment: 1 byte
type SSID struct {
    Data     [32]byte  // 32 bytes (32 * 1 byte)
    bitmask  uint8     // 1 byte
}



func (s *SSID) AddSSID(bytes []byte) bool {
	length := len(bytes)

	if length > 32 || length < 1 { return false }

    s.setLen(length)
	copy(s.Data[:length], bytes)
	
	return true
}



func (s *SSID) setLen(length int) {
    s.bitmask = (s.bitmask &^ ssidLenMask) | (uint8(length) & ssidLenMask)
}



func (s *SSID) Len() int {
    return int(s.bitmask & ssidLenMask)
}


func (s *SSID) IsHidden() bool {
    return (s.bitmask & ssidHiddenMask) != 0
}


func (s *SSID) IsUnknown() bool {
    return (s.bitmask & ssidUnknownMask) != 0
}



func (s *SSID) SetHidden(hidden bool) {
    if hidden {
        s.bitmask |= ssidHiddenMask
    } else {
        s.bitmask &^= ssidHiddenMask
    }
}



func (s *SSID) SetUnknown(unknown bool) {
    if unknown {
        s.bitmask |= ssidUnknownMask
    } else {
        s.bitmask &^= ssidUnknownMask
    }
}



func (s *SSID) String() string {
    if s.IsUnknown() { return "unknown"  }
    if s.IsHidden()  { return "<hidden>" }

    length := s.Len()

    if length == 0 { return "<empty>"  }

    return string(s.Data[:length])
}