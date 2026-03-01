package deauth

import (
	"fmt"
	"offscan/utils"

	"github.com/jessevdk/go-flags"
)



type DeauthArgs struct {
    Iface     string `short:"i" long:"iface" description:"Network interface" required:"true"`
    TargetMac string `short:"t" long:"target-mac" description:"Target MAC" required:"true"`
    Bssid     string `short:"b" long:"bssid" description:"BSSID" required:"true"`
    Delay     int    `short:"d" long:"delay" default:"30" description:"Delay in ms"`
    Channel   int    `short:"c" long:"channel" description:"Channel" required:"true"`
}



func ParseArgs(args []string) *DeauthArgs {
    var opts DeauthArgs
    
    parser := flags.NewParser(&opts, flags.None)
    _, err := parser.ParseArgs(args)
    
    if err != nil {
        utils.Abort(fmt.Sprintf("Unable to create the deauth argument parser: %v", err))
    }
    
    return &opts
}