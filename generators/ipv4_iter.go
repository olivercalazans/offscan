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
	"net"
	"offscan/conv"
	"offscan/utils"
	"strconv"
	"strings"
)



type Ipv4Iter struct {
    current  uint32
    end      uint32
    total    uint64
    StartU32 uint32
    EndU32   uint32
}



func NewIpv4Iter(cidr string, rangeStr *string) *Ipv4Iter {
    networkU32, broadcastU32 := parseCIDR(cidr)

    usableStart   := networkU32 + 1
    usableEnd     := broadcastU32 - 1
    cidrHasUsable := usableStart <= usableEnd

    var startRange, endRange uint32
    
    if rangeStr != nil && *rangeStr != "" {
        s := strings.TrimSpace(*rangeStr)
        startRange, endRange  = parseRange(s, usableStart, usableEnd, cidrHasUsable)
    
	} else {
        if cidrHasUsable {
            startRange, endRange = usableStart, usableEnd
        } else {
            startRange, endRange = networkU32, networkU32
        }
    }

    if startRange > endRange {
        utils.Abort("Start IP cannot be greater than end IP")
    }

    total := uint64(endRange - startRange + 1)
    
    return &Ipv4Iter{
        current:  startRange,
        end:      endRange,
        total:    total,
        StartU32: startRange,
        EndU32:   endRange,
    }
}



func parseCIDR(cidr string) (network, broadcast uint32) {
    parts := strings.Split(cidr, "/")
    
	if len(parts) != 2 {
        utils.Abort(fmt.Sprintf("Invalid CIDR: %s", cidr))
    }

    ip := net.ParseIP(parts[0])
    if ip == nil {
        utils.Abort(fmt.Sprintf("Invalid IP in CIDR '%s'", cidr))
    }
    
	ip = ip.To4()
    if ip == nil {
        utils.Abort(fmt.Sprintf("CIDR '%s' is not IPv4", cidr))
    }

    prefix, err := strconv.Atoi(parts[1])
    if err != nil || prefix < 0 || prefix > 32 {
        utils.Abort(fmt.Sprintf("Invalid prefix in CIDR '%s'", cidr))
    }

    ipU32 := conv.IPToU32(ip)

    var mask uint32
    if prefix == 0 {
        mask = 0
    } else {
        mask = ^uint32(0) << (32 - uint(prefix))
    }

    network   = ipU32 & mask
    broadcast = network | ^mask
    
	return network, broadcast
}



func parseRange(
	r 			  string,  
	usableStart   uint32, 
	usableEnd     uint32, 
	cidrHasUsable bool,
) (uint32, uint32) {
    if strings.Contains(r, "*") {
        return parseWildcardRange(r, usableStart, usableEnd, cidrHasUsable)
    }

	return parseSingleIPRange(r)
}



func parseSingleIPRange(ipStr string) (uint32, uint32) {
    ip    := parseIPAddress(ipStr)
	ipU32 := conv.IPToU32(ip)
    return ipU32, ipU32
}



func parseWildcardRange(
	rangeStr      string, 
	usableStart   uint32, 
	usableEnd     uint32, 
	cidrHasUsable bool,
) (uint32, uint32) {
	parts := strings.SplitN(rangeStr, "*", 2)
    
	if len(parts) != 2 {
        utils.Abort(fmt.Sprintf("Invalid range format: %s", rangeStr))
    }

	startPart := strings.TrimSpace(parts[0])
    endPart   := strings.TrimSpace(parts[1])

    var startIP *uint32
    var startInCidr bool

	if startPart != "" {
        ip         := parseIPAddress(startPart)
		ipU32      := conv.IPToU32(ip)
        startIP     = &ipU32
        startInCidr = cidrHasUsable && ipU32 >= usableStart && ipU32 <= usableEnd
    }

	var endIP *uint32
    var endInCidr bool

	if endPart != "" {
        ip       := parseIPAddress(endPart)
		ipU32 	 := conv.IPToU32(ip)
        endIP     = &ipU32
        endInCidr = cidrHasUsable && ipU32 >= usableStart && ipU32 <= usableEnd
    }

    switch {
    case startPart != "" && endPart != "":
        return *startIP, *endIP

    case startPart != "" && endPart == "":
        if !startInCidr {
    		ip := conv.U32ToIP(*startIP)
		    utils.Abort(fmt.Sprintf("Start IP %s is outside CIDR range. When using 'IP*', the IP must be within the CIDR", ip.String()))
		}
        
		return *startIP, usableEnd

    case startPart == "" && endPart != "":
        if !endInCidr {
            ip := conv.U32ToIP(*endIP)
            utils.Abort(
                fmt.Sprintf("End IP %s is outside CIDR range. When using '*IP', the IP must be within the CIDR", ip.String()),
            )
        }
        
		return usableStart, *endIP

    case startPart == "" && endPart == "":
        if cidrHasUsable {
            return usableStart, usableEnd
        }
        return usableStart, usableStart

    default:
        utils.Abort("Unexpected wildcard parsing")
        return 0, 0
    }
}



func parseIPAddress(ipStr string) net.IP {
    ip := net.ParseIP(ipStr)
    if ip == nil {
        utils.Abort(fmt.Sprintf("Invalid IP address '%s'", ipStr))
    }

    ip4 := ip.To4()
    if ip4 == nil {
        utils.Abort(fmt.Sprintf("'%s' is not an IPv4 address", ipStr))
    }

    return ip4
}



func (it *Ipv4Iter) Next() (net.IP, bool) {
    if it.current > it.end {
        return nil, false
    }

    ip := conv.U32ToIP(it.current)
    it.current++
    return ip, true
}



func (it *Ipv4Iter) Total() uint64 {
    return it.total
}



func (it *Ipv4Iter) Reset() {
    it.current = it.StartU32
}