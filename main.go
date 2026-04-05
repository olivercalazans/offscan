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
	"offscan/engines/floodping"
	"offscan/engines/floodtcp"
	"offscan/engines/hostdisc"
	"offscan/engines/netinfo"
	"offscan/engines/portscan"
	"offscan/engines/wifimap"
	"offscan/internal/utils"
)



type CommandHandler struct {
	Description string
	Run         func(args []string)
}



var registry = map[string]CommandHandler{
	"beacon": {
		Description: "Beacon Flood",
		Run:         beacon.Run,
	},
	"deauth": {
		Description: "Deauthentication attack",
		Run:         deauth.Run,
	},
	"info": {
		Description: "Network Information",
		Run:         netinfo.Run,
	},
	"hdisc": {
		Description: "Host Discovery",
		Run:         hostdisc.Run,
	},
	"ping": {
		Description: "Ping Flooding",
		Run:         floodping.Run,
	},
	"pscan": {
		Description: "Port Scanning",
		Run:         portscan.Run,
	},
	"tcp": {
		Description: "TCP Flooding",
		Run:         floodtcp.Run,
	},
	"wmap": {
		Description: "Wifi Mapping",
		Run:         wifimap.Run,
	},
}



func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		utils.Abort("No input found")
	}

	cmdName := args[0]

	if cmdName == "-h" || cmdName == "--help" {
		displayCommands()
		return
	}

	engine, ok := registry[cmdName]
	if !ok {
		utils.Abort(fmt.Sprintf("No command '%s'", cmdName))
	}

	engine.Run(args[1:])
}



func displayCommands() {
	fmt.Println("# Available commands:")
	
    for name, handler := range registry {
		fmt.Printf("  %-6s -> %s\n", name, handler.Description)
	}
	
    fmt.Println()
}