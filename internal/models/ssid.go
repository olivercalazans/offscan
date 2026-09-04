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



type SSID struct {
	Data       [32]byte
	length     uint8
	IsUnknown  bool
	IsHidden   bool
}



func (s *SSID) AddSSID(bytes []byte) bool {
	lenBytes := len(bytes)

	if lenBytes > 32 || lenBytes < 1 { return false }

	s.length = uint8(len(bytes))
	copy(s.Data[:s.length], bytes)
	
	return true
}



func (s *SSID) Len() int {
	return int(s.length)
}



func (s *SSID) String() string {
    if s.IsUnknown { return "unknown"  }
    if s.IsHidden  { return "<hidden>" }
    if s.length == 0  { return "<empty>"  }

    return string(s.Data[:s.length])
}