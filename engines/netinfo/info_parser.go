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

package netinfo

import (
	"offscan/internal/argparser"
)


type netInfoParser struct {
    Iface  string
}


const iface uint8 = 1	



func newParser() netInfoParser {
	return netInfoParser{}
}



func FlagSettings() []argparser.Flag {
	return []argparser.Flag{
		{ID: 0, Desc: 
			"Network and Interface Information\nIt displays network interface configurations and status information\n\nE.g., $ sudo ./offscan info <FLAGS>",
		},
		{ID: iface, Short: "i", Long: "iface", HasValue: true,  Desc: "Define a network interface to get information"},
	}
}



func (nip *netInfoParser) parseNetInfoArgs(args []string) {
    flags  := FlagSettings()
	parser := argparser.NewArgParser(flags, args)
	parser.ParseFlags()

	for _, flag := range flags {
		switch flag.ID {
		case iface : nip.Iface = flag.ValueStr
		}
	}
}