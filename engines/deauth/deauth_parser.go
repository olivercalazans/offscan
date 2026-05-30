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

package deauth

import (
	"net"
	"offscan/internal/argparser"
	"offscan/internal/conv"
)



type deauthParser struct {
    iface      *net.Interface 
    targetMac   net.HardwareAddr
    bssid       net.HardwareAddr
    delay       int
    channel     int
}


const (
	iface     uint8 = 1
	targetMac uint8 = 2
	bssid     uint8 = 3
	delay     uint8 = 4
	channel   uint8 = 5
)



func newParser() *deauthParser {
	return &deauthParser{}
}



func (dp *deauthParser) parseDeauthArgs(args []string) {
    flags := []argparser.Flag{
		{ID: iface,     Short: "i", Long: "iface",   HasValue: true, Desc: "Network interface to send frames"},
		{ID: targetMac, Short: "t", Long: "tmac",    HasValue: true, Desc: "Target MAC"},		
		{ID: bssid,     Short: "b", Long: "bssid",   HasValue: true, Desc: "BSSID"},		
		{ID: delay,     Short: "d", Long: "delay",   HasValue: true, Desc: "Delay in ms"},		
		{ID: channel,   Short: "c", Long: "channel", HasValue: true, Desc: "Channel"},		
	}

	parser := argparser.NewArgParser(flags, args)
	parser.ParseFlags()

	for _, flag := range flags {    
		switch flag.ID {
		case iface     : dp.iface     = conv.MustStrToIface(flag.ValueStr)
		case targetMac : dp.targetMac = conv.MustStrToMac(flag.ValueStr)
		case bssid     : dp.bssid     = conv.MustStrToMac(flag.ValueStr)
		case delay     : dp.delay     = conv.StrToInt(flag.ValueStr)
		case channel   : dp.channel   = conv.StrToInt(flag.ValueStr)
		}
	}
}