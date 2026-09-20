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
)



func DisplayHelp() {
	help := "\n### BEACON FLOODER\n\n" +
			"     E.g.,: $ sudo ./offscan beacon <FLAGS>\n\n" +
	        "    -c, --channel <INT> : (Required) Channel\n" +
	        "    -i, --iface <IFACE> : (Required) Network interface to send frames\n" +
	        "    -s, --ssid <SSID>   : (Required) SSID/Network name\n"
	
	fmt.Println(help)
}



type beaconFloodParser struct {
	engine  *beaconFlood
	parser  *argparser.ArgParser
}



func (bf *beaconFlood) parseArgs(args []string) {
	bfp := beaconFloodParser{}
	
	bfp.engine = bf
	bfp.parser = argparser.NewArgParser(args)

	bfp.parseIface()
	bfp.parseSSID()
	bfp.parseChannel()
	bfp.parser.AbortIfHasError()
}



func (bfp *beaconFloodParser) parseIface() {
	arg := argparser.Argument{
		Long: "--iface", Short: "-i", Required: true,
	}

	iface, _ := bfp.parser.Iface(&arg)
	bfp.engine.iface = iface
}



func (bfp *beaconFloodParser) parseSSID() {
	arg := argparser.Argument{
		Long: "--ssid", Short: "-s", Required: true,
	}

	ssid, _ := bfp.parser.String(&arg)

	if len(ssid) > 32 {
		err := fmt.Errorf("SSID bigger than 32 chars")
		bfp.parser.AddError(&arg, err)
		return
	}

	bfp.engine.ssid = ssid
}



func (bfp *beaconFloodParser) parseChannel() {
	arg := argparser.Argument{
		Long: "--channel", Short: "-c", Required: true,
	}

	chnl, _ := bfp.parser.Int(&arg)

	if chnl < 1 {
		err := fmt.Errorf("Channel can not be zero or negative")
		bfp.parser.AddError(&arg, err)
		return
	}

	bfp.engine.channel = uint8(chnl)
}