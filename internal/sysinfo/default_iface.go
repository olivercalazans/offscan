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

package sysinfo

import (
	"fmt"
	"net"
	"offscan/internal/utils"
)



func MustDefaultInterface() *net.Interface {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        utils.Abort(fmt.Sprintf("Failed to bind UDP socket: %v", err))
    }
    defer conn.Close()

    localAddr  := conn.LocalAddr().(*net.UDPAddr)
    interfaces := MustAllIfaces()

    for _, iface := range interfaces {
        if iface.Flags&net.FlagUp == 0 {
            continue
        }

        addrs, err := iface.Addrs()
        if err != nil {
            continue
        }

        for _, addr := range addrs {
            ipNet, ok := addr.(*net.IPNet)
            
			if !ok {
                continue
            }
            
			if ipNet.IP.Equal(localAddr.IP) {
                return &iface
            }
        }
    }

    utils.Abort(fmt.Sprintf("No interface found with IP %s", localAddr.IP))
	return nil
}