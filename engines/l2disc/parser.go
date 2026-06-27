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
	"math"
	"offscan/internal/argparser"
	"offscan/internal/conv"
	"offscan/internal/utils"
	"strconv"
	"time"
)



func DisplayHelp() {
	help := "\n# Layer 2 Host Discovery. E.g., $ sudo ./offscan l2disc <FLAGS>\n\n" +
	        "    -i, --iface <IFACE> : (Required) Define a network interface to sniff frames\n" +
	        "    -t, --time <RANGE>  : (Optional) Time in seconds to sniff each channel (Default 1s)\n"

	fmt.Println(help)
}



const (
	iface      uint8 = 1
	sniffTime  uint8 = 2
	retrys     uint8 = 3
)



func FlagSettings() []argparser.Flag {
	return []argparser.Flag{
		{ ID: iface,     Short: "i", Long: "iface", HasValue: true, Req: true },
		{ ID: sniffTime, Short: "t", Long: "time",  HasValue: true },
	}
}



func (l2hd *layer2HostDiscovery) parseArgs(args []string) {
    flags  := FlagSettings()
	parser := argparser.NewArgParser(flags)
	parser.ParseFlags(args)
	args = nil

	for _, flag := range flags {
		switch flag.ID {
		case iface     : l2hd.iface = conv.MustStrToIface(flag.ValueStr)
		case sniffTime : l2hd.calculateDuration(flag.ValueStr)
		}
	}

	l2hd.errChnls = make(map[int]struct{})
}



func (l2hd *layer2HostDiscovery) calculateDuration(strTime string) {
	sniffTime      := parseFloat(strTime)
	nano           := math.Round(sniffTime * float64(time.Second))
	l2hd.sniffTime  = time.Duration(nano)
}



func parseFloat(str string) float64 {
	if str == "" { return 1 }
	
	value, err := strconv.ParseFloat(str, 64)

	if err != nil {
		utils.Abort(fmt.Sprintf("Invalid value for time duration: %v", err))
	}

	if value <= 0 {
		utils.Abort(fmt.Sprintf("Sniffing time can't be negative: %v", err))
	}

	return value
}