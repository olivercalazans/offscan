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
	"fmt"
	"net"
	"offscan/internal/models"
	"offscan/internal/utils"
)



func IfaceIPv4(iface *net.Interface) (models.IPv4, error) {
    var ip models.IPv4

    addrs, err := iface.Addrs()
    if err != nil {
        return ip, fmt.Errorf("failed to get addresses for %s: %w", iface.Name, err)
    }

    for _, addr := range addrs {
        ipNet, ok := addr.(*net.IPNet)
        if !ok { continue }

        ip4 := ipNet.IP.To4()
        if ip4 == nil { continue }

        return models.NetIpToIPv4(ip4), nil
    }

    return ip, fmt.Errorf("no IPv4 address found on interface %s", iface.Name)
}



func MustIPv4(iface *net.Interface) models.IPv4 {
    ip, err := IfaceIPv4(iface)

    if err != nil {
        utils.Abort(fmt.Sprintf("%v", err))
    }

    return ip
}