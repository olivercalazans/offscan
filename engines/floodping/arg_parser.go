package floodping

import (
	"fmt"
	"offscan/utils"
	"os"

	"github.com/jessevdk/go-flags"
)



type PingArgs struct {
    DstIP   string  `long:"dip" description:"Destination IP address to flood" required:"true"`
    DstMAC  string  `long:"dmac" description:"Destination MAC address. 'local' = iface MAC, 'gateway' = gateway MAC" required:"true"`
    SrcIP   string `long:"sip" description:"Source IP address (optional)"`
    SrcMAC  string `long:"smac" description:"Source MAC address. Default: Random. 'local' = iface MAC, 'gateway' = gateway MAC"`
}



func ParsePingArgs(args []string) *PingArgs {
    var opts PingArgs
    
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