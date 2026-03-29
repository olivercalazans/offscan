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

package ifaceinfo

import (
	"encoding/binary"
	"fmt"
	"net"
)



func BroadcastFromCIDR(cidr string) (net.IP, error) {
    ip, ipnet, err := net.ParseCIDR(cidr)
    if err != nil {
        return nil, fmt.Errorf("Invalid CIDR: %w", err)
    }

	ipv4 := ip.To4()
    if ipv4 == nil {
        return nil, fmt.Errorf("CIDR is not IPv4")
    }

    ipU32 := binary.BigEndian.Uint32(ipv4)
    mask  := binary.BigEndian.Uint32(ipnet.Mask)

    broadcastU32 := ipU32 | ^mask
    broadcast    := make(net.IP, 4)
    binary.BigEndian.PutUint32(broadcast, broadcastU32)
    
	return broadcast, nil
}