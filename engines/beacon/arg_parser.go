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
	"net"
	"offscan/internal/conv"
	"offscan/internal/utils"
	"os"

	"github.com/jessevdk/go-flags"
)



type BcFloodArgs struct {
	Ssid    string
	Iface   *net.Interface
	Channel int
}



type Args struct {
    Ssid    string `short:"s" long:"ssid" description:"SSID/Network name" required:"true"`
    Iface   string `short:"i" long:"iface" description:"Interface to be used" required:"true"`
    Channel int    `short:"c" long:"channel" description:"Channel" required:"true"`
}



func parseArgs(argList []string) *BcFloodArgs {
    var opts Args

	parser := flags.NewParser(&opts, flags.HelpFlag)
    _, err := parser.ParseArgs(argList)

	if err != nil {
		if flags.WroteHelp(err) {
			fmt.Printf("%v", err)
			os.Exit(0)
		}
		
		utils.Abort(fmt.Sprintf("Unable to create argument parser: %v", err))
    }

	bcArgs := &BcFloodArgs{
		Ssid:    opts.Ssid,
		Iface:   conv.MustGetIface(opts.Iface),
		Channel: opts.Channel,
	}

	return bcArgs
}