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

package generators

import (
	"fmt"
	"math/rand"
	"offscan/internal/utils"
	"sort"
	"strconv"
	"strings"
)



type PortIter struct {
    ports []uint16
    index int
}



func NewPortIter(portsStr *string, random bool) *PortIter {
    var portsSet map[uint16]bool

    if portsStr == nil || *portsStr == "" {
        portsSet = getDefaultPortsSet()
    } else {
        portsSet = parsePorts(*portsStr)
    }


	ports := make([]uint16, 0, len(portsSet))
    for p := range portsSet {
        ports = append(ports, p)
    }


	if !random {
        sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
    } else {
		rand.Shuffle(len(ports), func(i, j int) {
            ports[i], ports[j] = ports[j], ports[i]
        })
    }

    return &PortIter{
        ports: ports,
        index: 0,
    }
}



func getDefaultPortsSet() map[uint16]bool {
    defaultPorts := []uint16{
        20,     21,    22,    23,    25,    53,     67,     68,     69,     80,
        110,    139,   143,   161,   179,   194,    443,    445,    465,    514,
        531,    543,   550,   587,   631,   636,    993,    995,    1080,   1433,
        1434,   1500,  1521,  1723,  1883,  2049,   2181,   3306,   3372,   3389,
        3690,   4500,  5000,  5001,  5353,  5432,   5800,   5900,   6379,   7070,
        7777,   7778,  8000,  8080,  8443,  8888,   10000,  11211,  20000,  27017, 
        50000,  52000,
    }

    set := make(map[uint16]bool, len(defaultPorts))
    
	for _, p := range defaultPorts {
        set[p] = true
    }

    return set
}



func parsePorts(portsStr string) map[uint16]bool {
    set := make(map[uint16]bool)

    for part := range strings.SplitSeq(portsStr, ",") {
        part = strings.TrimSpace(part)
        
		if part == "" {
            continue
        }

        if strings.Contains(part, "-") {
			rangePorts := parsePortRange(part)

			for _, p := range rangePorts {
                set[p] = true
            }

		} else {
            p := validatePort(part)
			set[p] = true
        }
    }

    return set
}



func parsePortRange(rangeStr string) []uint16 {
    parts := strings.SplitN(rangeStr, "-", 2)
    
	if len(parts) != 2 {
        utils.Abort(fmt.Sprintf("Invalid port range format: %s", rangeStr))
    }

    start := validatePort(strings.TrimSpace(parts[0]))
    end   := validatePort(strings.TrimSpace(parts[1]))

    if start >= end {
        utils.Abort(fmt.Sprintf("Invalid range: %d-%d (start must be less than end)", start, end))
    }

    ports := make([]uint16, 0, end-start+1)
    
	for p := start; p <= end; p++ {
        ports = append(ports, p)
    }
    
	return ports
}



func validatePort(portStr string) uint16 {
    port, err := strconv.ParseUint(portStr, 10, 16)

	if err != nil {
		utils.Abort(fmt.Sprintf("Invalid port '%s': must be a number between 1 and 65535", portStr))
    }

	if port == 0 {
        utils.Abort("Port 0 is reserved and cannot be used")
    }

	return uint16(port)
}



func (pi *PortIter) Next() (uint16, bool) {
    if pi.index >= len(pi.ports) {
        return 0, false
    }
 
	port := pi.ports[pi.index]
    pi.index++
    
	return port, true
}



func (pi *PortIter) Len() int {
    return len(pi.ports)
}