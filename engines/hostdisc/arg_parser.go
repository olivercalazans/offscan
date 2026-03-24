package hostdisc

import (
	"fmt"
	"offscan/utils"
	"os"

	"github.com/jessevdk/go-flags"
)



type HostDiscArgs struct {
    Delay  string  `short:"d" long:"delay" default:"0.03" description:"Add a delay between packet transmissions."`
    Iface *string  `short:"i" long:"iface" description:"Network interface to send packets (default: system default)"`
    Range *string  `short:"r" long:"range" description:"IP range to scan"`
    Icmp   bool    `long:"icmp" description:"Use only/and ICMP probes"`
    Tcp    bool    `long:"tcp" description:"Use only/and TCP probes"`
    Udp    bool    `long:"udp" description:"Use only/and UDP probes"`
}



func ParseNetMapArgs(args []string) *HostDiscArgs {
    var opts HostDiscArgs
    
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