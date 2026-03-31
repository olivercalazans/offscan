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
	"net"
	"offscan/internal/utils"
)



func SrcIPFromDstIP(dstIP net.IP) net.IP {
    dst := dstIP.String() + ":53"

    conn, err := net.Dial("udp", dst)
    if err != nil {
        utils.Abort("Failed to connect UDP socket: " + err.Error())
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)
    ip := localAddr.IP

    if ip.To4() == nil {
        utils.Abort("Expected a local IPv4 address, but got IPv6")
    }

    return ip
}