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
	"strings"
)



func GatewayMAC(iface *net.Interface) (net.HardwareAddr, error) {
    data, err := os.ReadFile("/proc/net/arp")

	if err != nil {
        return nil, err
    }

	lines := strings.Split(string(data), "\n")
    for _, line := range lines[1:] {
        fields := strings.Fields(line)

		if len(fields) < 6 {
            continue
        }

		if fields[5] != iface.Name {
            continue
        }

		macStr := fields[3]
        if macStr == "00:00:00:00:00:00" {
            continue
        }

		mac, err := net.ParseMAC(macStr)
        if err != nil {
            continue
        }

		return mac, nil
    }

	return nil, fmt.Errorf("Gateway MAC not found")
}