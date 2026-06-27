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
	"fmt"
	"offscan/internal/argparser"
	"offscan/internal/conv"
	"offscan/internal/netroute"
	"offscan/internal/sysconf"
)



func DisplayHelp() {
	help := "\n# ARP Poisoning. E.g.,: $ sudo ./offscan arp <FLAGS>\n\n" +
	        "    --tip <IP>   : (Required) Target IP\n" +
	        "    --tmac <MAC> : (Required) Target MAC\n"
	
	fmt.Println(help)
}



const (
	targetIP   uint8 = 1
	targetMAC  uint8 = 2
)



func FlagSettings() []argparser.Flag {
	return []argparser.Flag{
		{ID: targetIP,  Long: "tip",  HasValue: true, Req: true},
		{ID: targetMAC, Long: "tmac", HasValue: true, Req: true},
	}
}



func (ap *arpPoison) parseArgs(args []string) {
	flags  := FlagSettings()
	parser := argparser.NewArgParser(flags)
	parser.ParseFlags(args)
	args = nil
	
	ap.addrs = addresses{}

	for _, flag := range flags {    
		switch flag.ID {
		case targetIP  : ap.addrs.targetIP  = conv.MustStrToIPv4(flag.ValueStr)
		case targetMAC : ap.addrs.targetMAC = conv.MustStrToMac(flag.ValueStr)
		}
	}

	ap.iface       = netroute.MustRouteIfaceForDstIP(ap.addrs.targetIP)
	ap.addrs.myMAC = ap.iface.HardwareAddr
	ap.addrs.apMAC = sysconf.MustGatewayMAC(&ap.iface)
	ap.addrs.apIP  = sysconf.MustGatewayIP(&ap.iface)
}