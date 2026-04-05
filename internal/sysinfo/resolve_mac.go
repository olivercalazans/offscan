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
	"fmt"
	"net"
	"offscan/internal/ifaceinfo"
	"offscan/internal/utils"
)



func ResolveMac(macStr string, iface *net.Interface) net.HardwareAddr {
    var mac net.HardwareAddr
    var err error

    switch macStr {
    case "":        return  nil
    case "gateway": mac, err = ifaceinfo.GatewayMAC(iface)
    case "local":   mac, err = iface.HardwareAddr, nil
    default:        mac, err = net.ParseMAC(macStr)
    }

    if err != nil {
        utils.Abort(fmt.Sprintf("Unable to parse MAC address: %v", err))
    }

    return mac
}



func MustResolveMac(macStr string, iface *net.Interface) net.HardwareAddr {
    mac := ResolveMac(macStr, iface)

    if mac == nil {
        utils.Abort("No MAC address found")
    }

    return mac
}