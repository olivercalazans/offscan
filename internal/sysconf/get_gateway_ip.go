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

package sysconf

import (
	"errors"
	"fmt"
	"net"
	"offscan/internal/models"
	"offscan/internal/utils"
	"os"
	"strconv"
	"strings"
)



func GatewayIP(iface *net.Interface) (models.IPv4, error) {
    var ip models.IPv4
    data, err := os.ReadFile("/proc/net/route")
    
	if err != nil {
        return ip, err
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

	return ip, fmt.Errorf("Gateway not found")
}



func hexToIP(hex string) (models.IPv4, error) {
    var ip models.IPv4
    
    if len(hex) != 8 {
        return ip, errors.New("invalid hex length: need 8 characters")
    }

    for i := range 4 {
        val, err := strconv.ParseUint(hex[i*2 : i*2+2], 16, 8)
        
        if err != nil {
            return ip, err
        }
    
        ip[i] = byte(val)
    }
    
    return ip, nil
}



func MustGatewayIP(iface *net.Interface) models.IPv4 {
    ip, err := GatewayIP(iface)

    if err != nil {
        utils.Abort(fmt.Sprintf("Unable to get Gateway IP. %v", err))
    }

    return ip
}