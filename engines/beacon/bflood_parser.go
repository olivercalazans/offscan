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

package beacon

import (
	"net"
	"offscan/internal/argparser"
	"offscan/internal/conv"
)



type bcFloodParser struct {
	ssid     string
	iface    net.Interface
	channel  int
}


const (
	iface    uint8 = 1
	ssid     uint8 = 2
	channel  uint8 = 3
)



func newParser() *bcFloodParser {
	return &bcFloodParser{}
}



func FlagSettings() []argparser.Flag {
	return []argparser.Flag{
		{ID: 0, Desc: "Beacon Flooder\nE.g.,: $ sudo ./offscan beacon <FLAGS>"},
		{ID: iface,   Short: "i", Long: "iface",   HasValue: true, Req: true, Desc: "Network interface to send frames"},
		{ID: ssid,    Short: "s", Long: "ssid",    HasValue: true, Req: true, Desc: "SSID/Network name"},		
		{ID: channel, Short: "c", Long: "channel", HasValue: true, Req: true, Desc: "Channel"},		
	}
}



func (bfp *bcFloodParser) parseBcFloodArgs(args []string) {
    flags  := FlagSettings()
	parser := argparser.NewArgParser(flags, args)
	parser.ParseFlags()

	for _, flag := range flags {    
		switch flag.ID {
		case iface   : bfp.iface   = conv.MustStrToIface(flag.ValueStr)
		case ssid    : bfp.ssid    = flag.ValueStr
		case channel : bfp.channel = conv.MustStrToInt(flag.ValueStr)
		}
	}
}