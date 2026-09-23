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
	"fmt"
	"offscan/internal/argparser"
	"time"
)



func DisplayHelp() {
	help := "\n### DEAUTHENTICATION ATTACK\n\n" + 
			"    E.g., $ sudo ./offscan deauth <FLAGS>\n\n" +
		    "    -b, --bssid <BSSID> : (Required) BSSID/AP MAC\n"+
	        "    -c, --channel <INT> : (Required) Channel\n" +
	        "    -i, --iface <IFACE> : (Required) Network interface to send frames\n" +
	        "    -t, --tmac <MAC>    : (Required) Target MAC\n"+
	        "    -d, --delay <INT>   : (Optional) Delay in ms\n"

	fmt.Println(help)
}



type deauthAttackParser struct {
	engine  *deauthAttack
	parser  *argparser.ArgParser
}



func (da *deauthAttack) parseArgs(args []string) {
	dap := deauthAttackParser{}
	
	dap.engine = da
	dap.parser = argparser.NewArgParser(args)

	dap.parseIface()
	dap.parseTargetMAC()
	dap.parseTargetBSSID()
	dap.parseChannel()
	dap.parseDelay()
	dap.parser.AbortIfHasError()
}



func (dap *deauthAttackParser) parseIface() {
	arg := argparser.Argument{
		Long: "--iface", Short: "-i", Required: true,
	}

	iface, _ := dap.parser.Iface(&arg)
	dap.engine.iface = iface
}



func (dap *deauthAttackParser) parseTargetMAC() {
	arg := argparser.Argument{
		Long: "--tmac", Short: "-t", Required: true,
	}

	mac, _ := dap.parser.MAC(&arg)
	dap.engine.targetMAC = mac
}



func (dap *deauthAttackParser) parseTargetBSSID() {
	arg := argparser.Argument{
		Long: "--bssid", Short: "-b", Required: true,
	}

	bssid, _ := dap.parser.MAC(&arg)
	dap.engine.apMAC = bssid 
}



func (dap *deauthAttackParser) parseChannel() {
	arg := argparser.Argument{
		Long: "--channel", Short: "-c", Required: true,
	}

	chnl, _ := dap.parser.Int(&arg)

	if chnl < 1 {
		err := fmt.Errorf("Channel can not be zero or negative")
		dap.parser.AddError(&arg, err)
		return
	}

	dap.engine.channel = chnl
}



func (dap *deauthAttackParser) parseDelay() time.Duration {
	arg := argparser.Argument{
		Long: "--delay", Short: "-d", Required: false,
	}

	var delay int = 30
	
	i, ok := dap.parser.Int(&arg)

	if ok { 
		delay = i
	}

	return time.Duration(delay) * time.Millisecond
}