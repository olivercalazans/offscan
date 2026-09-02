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

import (
	"encoding/hex"
	"errors"
	"fmt"
	"offscan/internal/utils"
)



type MAC [6]byte
type BSSID = MAC


func (m *MAC) String() string {
	buf := make([]byte, 17)
	
	hex.Encode(buf[0:2], m[0:1])
	buf[2] = ':'

	hex.Encode(buf[3:5], m[1:2])
	buf[5] = ':'

	hex.Encode(buf[6:8], m[2:3])
	buf[8] = ':'

	hex.Encode(buf[9:11], m[3:4])
	buf[11] = ':'

	hex.Encode(buf[12:14], m[4:5])
	buf[14] = ':'

	hex.Encode(buf[15:17], m[5:6])
	
	return string(buf)
}



var (
	ErrInvalidMACLength = errors.New("The MAC address must be exactly 17 characters long")
	ErrInvalidMACSep    = errors.New("Invalid MAC separator (use ':' or '-')")
	ErrInvalidMACHex    = errors.New("Invalid hexadecimal character in MAC address")
)



func ParseMAC(s string) (MAC, error) {
	var m MAC

	if len(s) != 17 {
		return m, ErrInvalidMACLength
	}

	byteIdx := 0
	for i := 0; i < 17; i += 3 {
		if i > 0 && s[i-1] != ':' && s[i-1] != '-' {
			return m, ErrInvalidMACSep
		}

		high, ok1 := fromHexChar(s[i])
		low,  ok2 := fromHexChar(s[i+1])

		if !ok1 || !ok2 {
			return m, ErrInvalidMACHex
		}

		m[byteIdx] = (high << 4) | low
		byteIdx++
	}

	return m, nil
}



func fromHexChar(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9': return c - '0', true
	case 'a' <= c && c <= 'f': return c - 'a' + 10, true
	case 'A' <= c && c <= 'F': return c - 'A' + 10, true
	}

	return 0, false
}



func MustParseMAC(str string) MAC {
	mac, err := ParseMAC(str)

	if err != nil {
		utils.Abort(err.Error())
	}

	return mac
}



func MustMacFromSlice(slc []byte) MAC {
	if len(slc) != 6 {
		utils.Abort(fmt.Sprintf("MustMacFromSlice: invalid slice length %d (expected 6)", len(slc)))
	}

	var m MAC
	copy(m[:], slc)
	
	return m
}