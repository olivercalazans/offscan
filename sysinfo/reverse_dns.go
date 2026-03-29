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
	"strings"
)



func GetHostName(ip string) string {
    names, err := net.LookupAddr(ip)

	if err != nil || len(names) < 1 {
        return "Unknown"
    }

    hostname := names[0]
    hostname  = strings.TrimSuffix(hostname, ".")
    hostname  = strings.TrimSuffix(hostname, ".lan")

    return hostname
}