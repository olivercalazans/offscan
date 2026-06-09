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

package arppoison

import (
	"net"
	"offscan/internal/ifaceinfo"
	"offscan/internal/netroute"
)



type arpPoison struct {
	iface      net.Interface
	targetIP   net.IP
	targetMAC  net.HardwareAddr
	apIP       net.IP
	apMAC	   net.HardwareAddr
}



func Run(args []string) {
    newArpPoison(args).execute()
}



func newArpPoison(args []string) *arpPoison {
	parser := newParser()
	parser.parseArpPoisonArgs(args)

	iface := netroute.MustRouteIfaceForDstIP(parser.targetIP)

	return &arpPoison{
		iface     : iface,
		targetIP  : parser.targetIP,
		targetMAC : parser.targetMAC,
		apIP      : ifaceinfo.MustGatewayIP(&iface),
		apMAC     : ifaceinfo.MustGatewayMAC(&iface),
	}
}



func (ap *arpPoison) execute() {

}