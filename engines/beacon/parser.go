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
	"fmt"
	"offscan/internal/argparser"
	"offscan/internal/conv"
	"offscan/internal/dot11build"
	"offscan/internal/generators"
	"offscan/internal/sockets"
)



func DisplayHelp() {
	help := "\n# Beacon Flooder. E.g.,: $ sudo ./offscan beacon <FLAGS>\n\n" +
	        "    -c, --channel <INT> : (Required) Channel\n" +
	        "    -i, --iface <IFACE> : (Required) Network interface to send frames\n" +
	        "    -s, --ssid <SSID>   : (Required) SSID/Network name\n"
	
	fmt.Println(help)
}



const (
	iface    uint8 = 1
	ssid     uint8 = 2
	channel  uint8 = 3
)



func FlagSettings() []argparser.Flag {
	return []argparser.Flag{
		{ID: iface,   Short: "i", Long: "iface",   HasValue: true, Req: true},
		{ID: ssid,    Short: "s", Long: "ssid",    HasValue: true, Req: true},
		{ID: channel, Short: "c", Long: "channel", HasValue: true, Req: true},
	}
}



func (bf *beaconFlood) parseArgs(args []string) {
    flags  := FlagSettings()
	parser := argparser.NewArgParser(flags)
	parser.ParseFlags(args)
	args = nil

	for _, flag := range flags {    
		switch flag.ID {
		case iface   : bf.iface   = conv.MustStrToIface(flag.ValueStr)
		case ssid    : bf.ssid    = flag.ValueStr
		case channel : bf.channel = uint8(conv.MustStrToInt(flag.ValueStr))
		}
	}

	bf.bcSent  = 0
	bf.builder = dot11build.NewBeacon()
	bf.socket  = sockets.NewL2Socket(&bf.iface)
    bf.randGen = generators.NewRandomValues()
}