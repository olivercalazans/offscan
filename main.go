package main

import (
	"fmt"
	"os"

	"offscan/engines/beacon"
	"offscan/engines/deauth"
	"offscan/engines/floodping"
	"offscan/engines/floodtcp"
	"offscan/engines/netinfo"
	"offscan/engines/netmap"
	"offscan/engines/portscan"
	"offscan/engines/wifimap"
	"offscan/utils"
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
	"netmap": {
		Description: "Network Mapping",
		Run:         netmap.Run,
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