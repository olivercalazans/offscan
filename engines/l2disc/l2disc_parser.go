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

package l2disc

import (
	"fmt"
	"net"
	"offscan/internal/argparser"
	"offscan/internal/conv"
	"offscan/internal/utils"
)


type l2DiscParser struct {
    Iface      net.Interface
	sniffTime  int
}



func newParser() l2DiscParser {
	return l2DiscParser{}
}



const (
	iface      uint8 = 1
	sniffTime  uint8 = 2
)


func FlagSettings() []argparser.Flag {
	return []argparser.Flag{
		{ID: 0, Desc: 
			"Layer 2 Host Discovery\nIt sniffs the 802.11 frames to discover active devices and which Access Point it is associated with\n\nE.g., $ sudo ./offscan l2disc <FLAGS>",
		},
		{
			ID: iface, Short: "i", Long: "iface", HasValue: true, Req: true,
			Desc: "Define a network interface to sniff frames",
		},
		{ID: sniffTime, Short: "t", Long: "time",  HasValue: true, Desc: "Time in seconds to sniff each channel (Default 1)"},
	}
}



func (l2dp *l2DiscParser) parseL2DiscArgs(args []string) {
    flags  := FlagSettings()
	parser := argparser.NewArgParser(flags, args)
	parser.ParseFlags()

	for _, flag := range flags {
		switch flag.ID {
		case iface     : l2dp.Iface     = conv.MustStrToIface(flag.ValueStr)
		case sniffTime : l2dp.sniffTime = parseSniffTime(flag.ValueStr)
		}
	}
}



func parseSniffTime(str string) int {
	if str == "" { return 1 }

	value := conv.MustStrToInt(str)
	if value <= 0 {
		utils.Abort(fmt.Sprintf("Sniffing time can't be negative: %d", value))
	}

	return value
}