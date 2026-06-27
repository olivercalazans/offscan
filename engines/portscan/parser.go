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

package portscan

import (
	"fmt"
	"offscan/internal/argparser"
	"offscan/internal/conv"
	"offscan/internal/netroute"
	"offscan/internal/sysconf"
)



func DisplayHelp() {
	help := "\n# Port Scanner. E.g., $ sudo ./offscan pscan <FLAGS>\n\n" +
	"    -t, --target <IP> : (Required) Target IP\n" +
	"    -p, --port <INT>  : (Optional) Specific ports or ranges\n" +
	"                          22,80 - Specific ports\n" +
	"                          20-50 - Port range\n" +
	"                          20,22-50 - Both can be used\n" +
	"    -r, --random      : (Optional) Scan ports in random order\n"

	fmt.Println(help)
}



const (
	target uint8 = 1
	ports  uint8 = 2
	random uint8 = 3
)



func FlagSettings() []argparser.Flag {
	return []argparser.Flag{
		{ID: target, Short: "t", Long: "target", HasValue: true, Req: true},
		{ID: ports,  Short: "p", Long: "ports",  HasValue: true},		
		{ID: random, Short: "r", Long: "random"},		
	}
}



func (ps *portScanner) parseArgs(args []string) {
    flags  := FlagSettings()
	parser := argparser.NewArgParser(flags)
	parser.ParseFlags(args)
	args = nil

	for _, flag := range flags {
		switch flag.ID {
		case target : ps.targetIP = conv.MustStrToIPv4(flag.ValueStr)
		case ports  : ps.ports    = flag.ValueStr
		case random : ps.random   = flag.ValueBool
		}
	}

	ps.iface     = netroute.MustRouteIfaceForDstIP(ps.targetIP)
	ps.myIP      = sysconf.MustIPv4(&ps.iface)
	ps.openPorts = make(map[uint16]struct{})
}