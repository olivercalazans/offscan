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

package netroute

import (
	"fmt"
	"net"
	"offscan/internal/utils"
)



func IsLocal(iface *net.Interface, ip net.IP) bool {
    addrs, err := iface.Addrs()
    if err != nil {
        utils.Abort(fmt.Sprintf("Unable to get interface addresses %s: %v", iface.Name, err))
    }

    for _, addr := range addrs {
        ipnet, ok := addr.(*net.IPNet)
        if !ok {
            continue
        }

        if ipnet.IP.To4() != nil && ip.To4() != nil {
            if ipnet.Contains(ip) {
                return true
            }
        }
    }

    return false
}