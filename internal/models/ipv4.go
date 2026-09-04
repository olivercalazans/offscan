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
	"fmt"
	"net"
	"offscan/internal/utils"
	"strconv"
)


type IPv4 [4]byte



func (ip IPv4) String() string {
    buf := [15]byte{}
    b   := buf[:0]

    for i, v := range ip {
        if i > 0 { b = append(b, '.') }
        b = strconv.AppendInt(b, int64(v), 10)
    }

    return string(b)
}



func (ip IPv4) Uint32() uint32 {
    return uint32(ip[0]) << 24 | uint32(ip[1]) << 16 | uint32(ip[2]) << 8 | uint32(ip[3])
}



func (ip IPv4) ToNetIP() net.IP {
    return net.IP(ip[:])
}



func ParseIPv4(s string) (IPv4, error) {
    var ip IPv4
    var idx int
    var val uint8
    var hasDigit bool

    for i := 0; i < len(s); i++ {
        c := s[i]

		if c == '.' {
            if idx >= 3 || !hasDigit {
                return ip, fmt.Errorf("Unable to parse %s to IPv4. Invalid format", s)
            }

            ip[idx] = val
            idx++
            val = 0
            hasDigit = false
            continue
        }

		if c < '0' || c > '9' {
            return ip, fmt.Errorf("Unable to parse %s to IPv4. Invalid character: %d", s, c)
        }

        if hasDigit {
            if val > 25 || (val == 25 && uint8(c-'0') > 5) {
                return ip, fmt.Errorf("Unable to parse %s to IPv4. Octet %d > 255", s, val)
            }
            
			val = val*10 + uint8(c-'0')
        } else {
            val = uint8(c - '0')
            hasDigit = true
        }
    }

	if idx != 3 || !hasDigit {
        return ip, fmt.Errorf("Unable to parse %s to IPv4. Invalid format", s)
    }

	ip[idx] = val
    return ip, nil
}



func MustParseIPv4(s string) IPv4 {
    ip, err := ParseIPv4(s)

	if err != nil {
        utils.Abort(err.Error())
    }

	return ip
}



func NetIpToIPv4(ip net.IP) IPv4 {
    var v4 IPv4
    
	if ip == nil {
        return v4
    }

	ip4 := ip.To4()
    if ip4 != nil {
        copy(v4[:], ip4)
    }

	return v4
}



func Uint32ToIPv4(x uint32) IPv4 {
    return IPv4{
        byte(x >> 24),
        byte(x >> 16),
        byte(x >> 8),
        byte(x),
    }
}