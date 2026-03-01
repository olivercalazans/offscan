package main

import (
	"fmt"
	"os"

	"offscan/engines/beacon"
	"offscan/engines/deauth"
	"offscan/engines/netinfo"
	"offscan/engines/netmap"
	"offscan/engines/ping"
	"offscan/engines/pscan"
	"offscan/engines/tcp"
	"offscan/engines/wmap"
	"offscan/utils"
)



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

    handler, ok := registry[cmdName]
    if !ok {
        utils.Abort(fmt.Sprintf("No command '%s'", cmdName))
    }

    if err := handler.Run(args[1:]); err != nil {
        utils.Abort(err.Error())
    }
}



func displayCommands() {
    fmt.Println("# Available commands:")
 
    for name, handler := range registry {
        fmt.Printf("  %-6s -> %s\n", name, handler.Description)
    }
 
    fmt.Println()
}



type CommandHandler struct {
    Description string
    Run         func(args []string) error
}



var registry = map[string]CommandHandler{
    "beacon": {
        Description: "Beacon Flood",
        Run:         beacon.Execute,
    },
    "deauth": {
        Description: "Deauthentication attack",
        Run:         deauth.Execute,
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
        Run:         ping.Run,
    },
    "pscan": {
        Description: "Port Scanning",
        Run:         pscan.Run,
    },
    "tcp": {
        Description: "TCP Flooding",
        Run:         tcp.Run,
    },
    "wmap": {
        Description: "Wifi Mapping",
        Run:         wmap.Run,
    },
}