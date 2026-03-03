package netmap

import (
	"fmt"
	"offscan/utils"

	"github.com/jessevdk/go-flags"
)



type NetMapArgs struct {
    Delay  string  `short:"d" long:"delay" default:"0.03" description:"Add a delay between packet transmissions."`
    Iface *string  `short:"i" long:"iface" description:"Network interface to send packets (default: system default)"`
    Range *string  `short:"r" long:"range" description:"IP range to scan"`
    Icmp   bool    `long:"icmp" description:"Use only/and ICMP probes"`
    Tcp    bool    `long:"tcp" description:"Use only/and TCP probes"`
    Udp    bool    `long:"udp" description:"Use only/and UDP probes"`
}



func ParseNetMapArgs(args []string) *NetMapArgs {
    var opts NetMapArgs
    
	parser := flags.NewParser(&opts, flags.None)
    _, err := parser.ParseArgs(args)
    
	if err != nil {
        utils.Abort(fmt.Sprintf("Unable to create argument parser: %v", err))
    }
    
	return &opts
}