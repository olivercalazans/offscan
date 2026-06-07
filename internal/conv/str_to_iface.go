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
