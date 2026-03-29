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
	"offscan/utils"
)



func IPv4(iface *net.Interface) (net.IP, error) {
    addrs, err := iface.Addrs()
    if err != nil {
        return nil, fmt.Errorf("Unable to get interface IPs: %w", err)
    }

    for _, addr := range addrs {
        ipNet, ok := addr.(*net.IPNet)
     
        if !ok {
            continue
        }
     
        ip := ipNet.IP
        if ip.To4() == nil {
            continue
        }
     
        return ip, nil
    }
    
    return nil, fmt.Errorf("No IPv4 address found on interface")
}



func MustIPv4(iface *net.Interface) net.IP {
    ip, err := IPv4(iface)

    if err != nil {
        utils.Abort(fmt.Sprintf("%v", err))
    }

    return ip
}