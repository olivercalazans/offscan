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

package ifmode

import "offscan/internal/argparser"



type ifConfParser struct {
	Iface  string
	Man    bool
    Mon    bool
}


const (
	iface uint8 = 1
	mon   uint8 = 2
	man   uint8 = 3
)



func newParser() *ifConfParser {
	return &ifConfParser{}
}



func FlagSettings() []argparser.Flag {
	return []argparser.Flag{
		{ID: 0, Desc: 
			"Interface Configuration\nIt sets the network interface to monitor or managed mode\n\nE.g., $ sudo ./offscan mode <FLAGS>",
		},
		{ID: iface, Short: "i", Long: "iface", HasValue: true,  Req: true, Desc: "Interface to set mode"},
		{ID: mon,   Short: "",  Long: "mon",   HasValue: false, Desc: "Set interface on monitor mode"},
		{ID: man,   Short: "",  Long: "man",   HasValue: false, Desc: "Set interface on managed mode"},
	}
}



func (icp *ifConfParser) parseIfConfigArgs(args []string) {
    flags  := FlagSettings()
	parser := argparser.NewArgParser(flags, args)
	parser.ParseFlags()

	for _, flag := range flags {
		switch flag.ID {
		case iface : icp.Iface = flag.ValueStr
		case mon   : icp.Mon   = flag.ValueBool
		case man   : icp.Man   = flag.ValueBool
		}
	}
}