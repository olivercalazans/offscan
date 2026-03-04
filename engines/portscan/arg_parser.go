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