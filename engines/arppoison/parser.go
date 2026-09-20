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
	"fmt"
	"offscan/internal/argparser"
	"offscan/internal/models"
	"offscan/internal/netroute"
	"offscan/internal/sysconf"
)



func DisplayHelp() {
	help := "\n### ARP POISONING\n\n" +
			"    E.g.,: $ sudo ./offscan arp <FLAGS>\n\n" +
	        "    --tip <IP>   : (Required) Target IP\n" +
	        "    --tmac <MAC> : (Required) Target MAC\n"
	
	fmt.Println(help)
}



type arpPoisonParser struct {
	engine  *arpPoison
	parser  *argparser.ArgParser
}



func (ap *arpPoison) parseArgs(args []string) {
	ap.addrs  = addresses{}
	app      := arpPoisonParser{}

	app.engine = ap
	app.parser = argparser.NewArgParser(args)
	
	app.parseTargetMAC()
	app.parseTargetIP()
	app.parser.AbortIfHasError()

	ap.iface       = netroute.MustRouteIfaceForDstIP(ap.addrs.targetIP)
	ap.addrs.myMAC = models.MustMacFromSlice(ap.iface.HardwareAddr)
	ap.addrs.apMAC = sysconf.MustGatewayMAC(&ap.iface)
	ap.addrs.apIP  = sysconf.MustGatewayIP(&ap.iface)
}



func (app *arpPoisonParser) parseTargetIP() {
	arg := argparser.Argument{ Long: "--tip", Short: "", Required: true }

	ip, _ := app.parser.IP(&arg)
	app.engine.addrs.targetIP = ip
}



func (app *arpPoisonParser) parseTargetMAC() {
	arg := argparser.Argument{ Long: "--tmac", Short: "", Required: true }

	mac, _ := app.parser.MAC(&arg)
	app.engine.addrs.targetMAC = mac
}