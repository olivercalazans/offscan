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



func Type(iface *net.Interface) string {
    if IsWireless(iface) {
        return "Wireless"
    }

	data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/type", iface.Name))

	if err != nil {
        return "Unknown"
    }

	typ := strings.TrimSpace(string(data))

	switch typ {
    	case "1":   return "Ethernet"
    	case "772": return "Loopback"
    	default:    return "Type-" + typ
    }
}