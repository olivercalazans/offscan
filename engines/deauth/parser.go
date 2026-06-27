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
	"offscan/internal/argparser"
	"offscan/internal/conv"
	"offscan/internal/dot11build"
	"offscan/internal/sockets"
	"offscan/internal/utils"
	"time"
)



const (
	iface     uint8 = 1
	targetMac uint8 = 2
	bssid     uint8 = 3
	channel   uint8 = 4
	delay     uint8 = 5
)



func FlagSettings() []argparser.Flag {
	return []argparser.Flag{
		{ID: 0, Desc: "Deauthentication Attack\nE.g., $ sudo ./offscan deauth <FLAGS>"},
		{ID: iface,     Short: "i", Long: "iface",   HasValue: true, Req: true, Desc: "Network interface to send frames"},
		{ID: targetMac, Short: "t", Long: "tmac",    HasValue: true, Req: true, Desc: "Target MAC"},		
		{ID: bssid,     Short: "b", Long: "bssid",   HasValue: true, Req: true, Desc: "BSSID"},		
		{ID: channel,   Short: "c", Long: "channel", HasValue: true, Req: true, Desc: "Channel"},		
		{ID: delay,     Short: "d", Long: "delay",   HasValue: true, Desc: "Delay in ms"},
	}
}



func (da *deauthAttack) parseArgs(args []string) {
    flags  := FlagSettings()
	parser := argparser.NewArgParser(flags)
	parser.ParseFlags(args)
	args = nil
	
	for _, f := range flags {
		switch f.ID {
		case iface     : da.iface     = conv.MustStrToIface(f.ValueStr)
		case targetMac : da.targetMAC = conv.MustStrToMac(f.ValueStr)
		case bssid     : da.apMAC     = conv.MustStrToMac(f.ValueStr)
		case delay     : da.delay     = parseDelay(f.ValueStr)
		case channel   : da.channel   = conv.MustStrToInt(f.ValueStr)
		}
	}

	da.builder  = dot11build.NewDeauthFrame()
	da.frmsSent = 0
	da.seqNum   = 1
	da.socket   = sockets.NewL2Socket(&da.iface)
}



func parseDelay(str string) time.Duration {
	delay := utils.Pick(str == "", 30, conv.MustStrToInt(str))
	return time.Duration(delay) * time.Millisecond
}