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


func MustRouteIfaceForDstIP(dstIP net.IP) *net.Interface {
    dstIPv4 := dstIP.To4()
    if dstIPv4 == nil {
        utils.Abort(fmt.Sprintf("Destination IP is not IPv4: %s", dstIP))
    }

    dstAddr   := &net.UDPAddr{IP: dstIPv4, Port: 0}
    conn, err := net.DialUDP("udp", nil, dstAddr)
   
    if err != nil {
        utils.Abort(fmt.Sprintf("Failed to dial %s: %v", dstIPv4, err))
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)
    localIP   := localAddr.IP.To4()

    if localIP == nil {
        utils.Abort(fmt.Sprintf("Local address is not IPv4: %v", localAddr.IP))
    }


    interfaces, err := net.Interfaces()
    if err != nil {
        utils.Abort(fmt.Sprintf("failed to list interfaces: %v", err))
    }

    for _, iface := range interfaces {
        if iface.Flags & net.FlagUp == 0 {
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
            if ipNet.IP.Equal(localIP) {
                return &iface
            }
        }
    }

    utils.Abort(fmt.Sprintf("no interface found with IP %s", localIP))
    return nil
}