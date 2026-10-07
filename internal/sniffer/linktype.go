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

package sniffer

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// ARPHRD values from <linux/if_arp.h>
const (
	arphrdEthernet          = 1
	arphrdIEEE80211         = 801 // raw 802.11
	arphrdIEEE80211Radiotap = 803 // 802.11 + radiotap header
)



// LinktypeOf reads /sys/class/net/<iface>/type, which holds the ARPHRD_* value.
func LinktypeOf(iface net.Interface) (int, error) {
	b, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/type", iface.Name))
	if err != nil {
		return -1, fmt.Errorf("linktype: %w", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return -1, fmt.Errorf("linktype: parse %q: %w", b, err)
	}
	return n, nil
}