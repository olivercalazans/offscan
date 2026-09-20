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

package l2disc

import (
	"fmt"
	"offscan/internal/argparser"
	"time"
)



func DisplayHelp() {
	help := "\n### LAYER 2 HOST DISCOVERY\n\n" + 
			"    E.g., $ sudo ./offscan l2disc <FLAGS>\n\n" +
	        "    -i, --iface <IFACE> : (Required) Define a network interface to sniff frames\n" +
	        "    -d, --delay <FLOAT> : (Optional) Delay in seconds to sniff each channel (Default 1.5s)\n"

	fmt.Println(help)
}



func (l2hd *layer2HostDiscovery) parseArgs(args []string) {
	l2hdp := layer2HostDiscoveryParser{}

	l2hdp.engine = l2hd
	l2hdp.parser = argparser.NewArgParser(args)
	
	l2hdp.parseIface()
	l2hdp.parseDelay()
	l2hdp.parser.AbortIfHasError()
}



type layer2HostDiscoveryParser struct {
	engine  *layer2HostDiscovery
	parser  *argparser.ArgParser
}



func (l2hdp *layer2HostDiscoveryParser) parseIface() {
	arg := argparser.Argument{ Long: "--iface", Short: "-i", Required: true }

	iface, _ 		   := l2hdp.parser.Iface(&arg)
	l2hdp.engine.iface  = iface
}



func (l2hdp *layer2HostDiscoveryParser) parseDelay() {
	arg := argparser.Argument{ Long: "--delay", Short: "-i", Required: false }
	
	var delay float64 = 1.5

	if float, ok := l2hdp.parser.Float64(&arg); ok {
		delay = float
	}

	nano := delay * float64(time.Second)

	l2hdp.engine.sniffTime = time.Duration(nano)
}