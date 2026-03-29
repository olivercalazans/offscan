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

package utils

import (
	"encoding/binary"
	"fmt"
	"net"
)



func GetFirstAndLastIP(cidr string) (uint32, uint32) {
    _, ipnet, err := net.ParseCIDR(cidr)

	if err != nil {
        Abort(fmt.Sprintf("Invalid CIDR: %s", cidr))
    }

    network := binary.BigEndian.Uint32(ipnet.IP.To4())
    mask    := binary.BigEndian.Uint32(ipnet.Mask)

    broadcast := network | ^mask

    first := network + 1
    last  := broadcast - 1

    if first > last {
        Abort(fmt.Sprintf("No usable IPs in CIDR: %s", cidr))
    }

    return first, last
}