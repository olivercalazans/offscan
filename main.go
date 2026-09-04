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

	"offscan/engines/arppoison"
	"offscan/engines/beacon"
	"offscan/engines/deauth"
	"offscan/engines/fwd"
	"offscan/engines/hostdisc"
	"offscan/engines/ifmode"
	"offscan/engines/info"
	"offscan/engines/l2disc"
	"offscan/engines/pixiedust"
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
		"arp"    : { Run: arppoison.Run, Helper: arppoison.DisplayHelp },
		"beacon" : { Run: beacon.Run,    Helper: beacon.DisplayHelp    },
		"deauth" : { Run: deauth.Run,    Helper: deauth.DisplayHelp    },
		"fwd"    : { Run: fwd.Run,       Helper: fwd.DisplayHelp       },
		"hdisc"  : { Run: hostdisc.Run,  Helper: hostdisc.DisplayHelp  },
		"ifmode" : { Run: ifmode.Run,    Helper: ifmode.DisplayHelp    },
		"info"   : { Run: info.Run,      Helper: info.DisplayHelp      },
		"l2disc" : { Run: l2disc.Run,    Helper: l2disc.DisplayHelp    },
		"pixie"  : { Run: pixiedust.Run, Helper: pixiedust.DisplayHelp },
		"wmap"   : { Run: wifimap.Run,   Helper: wifimap.DisplayHelp   },
	}

	displayHeader()
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



func displayHeader() {
	fmt.Println("\nOffScan - The offensive security and scanning tool for Wi-Fi")
	fmt.Printf("Repository: https://github.com/olivercalazans/offscan\n\n")
}