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

package floodtcp

import (
	"fmt"
	"offscan/utils"
	"os"

	"github.com/jessevdk/go-flags"
)



type TcpArgs struct {
    DstIP   string  `long:"dip" description:"Target IP address to flood" required:"true"`
    DstMAC  string  `long:"dmac" description:"Destination MAC. Use 'local' = iface MAC, 'gateway' = gateway MAC" required:"true"`
    Port    uint16  `short:"p" long:"port" description:"Target port" required:"true"`
    SrcIP   string `long:"sip" description:"Optional source IP address"`
    SrcMAC  string `long:"smac" description:"Optional source MAC. Use 'local' = iface MAC, 'gateway' = gateway MAC"`
}



func ParseTcpArgs(args []string) *TcpArgs {
    var opts TcpArgs

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