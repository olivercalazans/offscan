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

package conv

import (
	"fmt"
	"net"
	"offscan/internal/utils"
	"strconv"
)


func StrToIface(ifaceName string) *net.Interface {
	if ifaceName == "" { return nil }

    iface, err := net.InterfaceByName(ifaceName)
    
	if err != nil {
        utils.Abort(fmt.Sprintf("Unable to get interface %s: %v", ifaceName, err))
    }
    
	return iface
}



func MustStrToIface(ifaceName string) net.Interface {
    iface := StrToIface(ifaceName)
    
	if iface == nil {
        utils.Abort("Missing interface name")
    }
    
	return *iface
}



func MustStrToInt(str string) int {
	value, err := strconv.Atoi(str)

	if err != nil {
		utils.Abort(fmt.Sprintf("Invalid value for int: %s", str))
	}

	return value
}



func StrToInt(str string) int {
	if str == "" { return 0 }
	
	value, err := strconv.Atoi(str)

	if err != nil {
		utils.Abort(fmt.Sprintf("Invalid value for int: %s", str))
	}

	return value
}



func MustStrToIPv4(s string) net.IP {
    ip := net.ParseIP(s)
    
	if ip == nil {
        utils.Abort(fmt.Sprintf("Invalid IP address: %s", s))
    }
    
	return MustTo4(ip)
}



func MustStrToMac(macStr string) net.HardwareAddr {    
	mac, err := net.ParseMAC(macStr)
    
	if err != nil {
        utils.Abort(fmt.Sprintf("Unable to parse MAC address: %v", err))
    }

	return mac
}