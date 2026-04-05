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
	"offscan/internal/utils"
)



func CIDR(iface *net.Interface) (string, error) {
    addrs, err := iface.Addrs()
    
	if err != nil {
        return "", err
    }
    
	for _, addr := range addrs {
        ipnet, ok := addr.(*net.IPNet)
    
		if !ok {
            continue
        }
    
		if ipnet.IP.To4() != nil {
            return ipnet.String(), nil
        }
    }
    
	return "", fmt.Errorf("No IPv4 address found")
}



func MustCIDR(iface *net.Interface) string {
    cidr, err := CIDR(iface)
    
    if err != nil {
        utils.Abort(fmt.Sprintf("Failed to get CIDR for interface %s: %v", iface.Name, err))
    }

    return cidr
}