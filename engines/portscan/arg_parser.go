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

package portscan

import (
	"fmt"
	"offscan/utils"
	"os"

	"github.com/jessevdk/go-flags"
)



type PortScanArgs struct {
    TargetIP   string  `short:"t" long:"target" description:"Target IP" required:"true"`
    Ports     *string `short:"p" long:"ports" description:"Specific ports or ranges (e.g., 22,80 or 20-50)"`
    Random     bool    `short:"r" long:"random" description:"Scan ports in random order"`
    Delay      string  `short:"d" long:"delay" default:"0.03" description:"Delay between packets (seconds)"`
    UDP        bool    `short:"U" long:"udp" description:"Scan UDP ports"`
}



func ParsePortScanArgs(args []string) *PortScanArgs {
    var opts PortScanArgs

	parser := flags.NewParser(&opts, flags.HelpFlag)
    _, err := parser.ParseArgs(args)

	if err != nil {
        if flags.WroteHelp(err) {
			fmt.Printf("%v", err)
			os.Exit(0)
		}
        
        utils.Abort(fmt.Sprintf("Unable to create argument parser: %v", err))
    }

	return &opts
}