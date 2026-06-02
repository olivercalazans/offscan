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
	"offscan/internal/argparser"
)



type portScanParser struct {
    TargetIP  string
    Ports     string
    Random    bool
}


const (
	target uint8 = 1
	ports  uint8 = 2
	random uint8 = 3
)



func newParser() *portScanParser {
	return &portScanParser{}
}



func FlagSettings() []argparser.Flag {
	return []argparser.Flag{
		{ID: 0, Desc: "Port Scanner\nIt scans a target to identify open ports\n\nE.g., $ sudo ./offscan pscan <FLAGS>"},
		{ID: target, Short: "t", Long: "target", HasValue: true,  Req: true,  Desc: "Target IP"},
		{ID: ports,  Short: "p", Long: "ports",  HasValue: true,  Desc: "Specific ports or ranges (e.g., 22,80 or 20-50)"},		
		{ID: random, Short: "r", Long: "random", HasValue: false, Desc: "Scan ports in random order"},		
	}
}



func (psp *portScanParser) parsePortScanArgs(args []string) {
    flags  := FlagSettings()
	parser := argparser.NewArgParser(flags, args)
	parser.ParseFlags()

	for _, flag := range flags {
		switch flag.ID {
		case target : psp.TargetIP = flag.ValueStr
		case ports  : psp.Ports    = flag.ValueStr
		case random : psp.Random   = flag.ValueBool
		}
	}
}