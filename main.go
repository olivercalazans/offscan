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

package main

import (
	"fmt"
	"os"

	"offscan/engines/beacon"
	"offscan/engines/deauth"
	"offscan/engines/hostdisc"
	"offscan/engines/ifmode"
	"offscan/engines/l2disc"
	"offscan/engines/netinfo"
	"offscan/engines/portscan"
	"offscan/engines/wifimap"
	"offscan/internal/argparser"
	"offscan/internal/utils"
)



func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		utils.Abort("No input found")
	}

	var registry = map[string]argparser.CommandHandler{
	"beacon" : { Run: beacon.Run,   FlagSettings: beacon.FlagSettings   },
	"deauth" : { Run: deauth.Run,   FlagSettings: deauth.FlagSettings   },
	"hdisc"  : { Run: hostdisc.Run, FlagSettings: hostdisc.FlagSettings },
	"info"   : { Run: netinfo.Run,  FlagSettings: netinfo.FlagSettings  },
	"l2disc" : { Run: l2disc.Run,   FlagSettings: l2disc.FlagSettings   },
	"mode"   : { Run: ifmode.Run,   FlagSettings: ifmode.FlagSettings   },
	"pscan"  : { Run: portscan.Run, FlagSettings: portscan.FlagSettings },
	"wmap"   : { Run: wifimap.Run,  FlagSettings: wifimap.FlagSettings  },
}

	cmdName := args[0]

	if cmdName == "--help" {
		argparser.DisplayAllHelp(registry)
		return
	}

	engine, ok := registry[cmdName]
	if !ok {
		argparser.DisplayAllHelp(registry)
		utils.Abort(fmt.Sprintf("No command '%s'", cmdName))
	}

	engine.Run(args[1:])
}