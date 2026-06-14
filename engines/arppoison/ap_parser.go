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
	"offscan/internal/argparser"
	"offscan/internal/conv"
)



type arpPoisonParser struct {
	targetIP   net.IP
	targetMAC  net.HardwareAddr
}


const (
	targetIP   uint8 = 1
	targetMAC  uint8 = 2
)


func newParser() *arpPoisonParser {
	return &arpPoisonParser{}
}



func FlagSettings() []argparser.Flag {
	return []argparser.Flag{
		{ID: 0, Desc: "ARP Poisoning\nE.g.,: $ sudo ./offscan arp <FLAGS>"},
		{ID: targetIP,  Long: "tip",  HasValue: true, Req: true, Desc: "Target IP"},
		{ID: targetMAC, Long: "tmac", HasValue: true, Req: true, Desc: "Target MAC"},
	}
}



func (app *arpPoisonParser) parseArpPoisonArgs(args []string) {
    flags  := FlagSettings()
	parser := argparser.NewArgParser(flags, args)
	parser.ParseFlags()

	for _, flag := range flags {    
		switch flag.ID {
		case targetIP  : app.targetIP  = conv.MustStrToIPv4(flag.ValueStr)
		case targetMAC : app.targetMAC = conv.MustStrToMac(flag.ValueStr)
		}
	}
}