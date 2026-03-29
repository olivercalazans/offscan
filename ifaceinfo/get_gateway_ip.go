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
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)



func GatewayIP(iface *net.Interface) (net.IP, error) {
    data, err := os.ReadFile("/proc/net/route")
    
	if err != nil {
        return nil, err
    }
    
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
        fields := strings.Fields(line)
        
		if len(fields) < 4 {
            continue
        }
        
		if fields[0] != iface.Name {
            continue
        }

		gateHex := fields[2]
        if gateHex == "00000000" {
            continue
        }

		ip, err := hexToIP(gateHex)
        if err != nil {
            continue
        }

		return ip, nil
    }

	return nil, fmt.Errorf("Gateway not found")
}



func hexToIP(hex string) (net.IP, error) {
    if len(hex) != 8 {
        return nil, fmt.Errorf("Invalid hex length")
    }

	b := make([]byte, 4)
    for i := 0; i < 4; i++ {
        val, err := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)

		if err != nil {
            return nil, err
        }
        b[3-i] = byte(val)
    }

	return net.IPv4(b[0], b[1], b[2], b[3]), nil
}