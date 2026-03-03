package wifimap

import (
	"fmt"
	"offscan/utils"

	"github.com/jessevdk/go-flags"
)


type WmapArgs struct {
    Iface   string `short:"i" long:"iface" description:"Interface to be used to get the beacons" required:"true"`
}



func ParseWmapArgs(args []string) *WmapArgs {
    var opts WmapArgs
    
	parser := flags.NewParser(&opts, flags.None)
    _, err := parser.ParseArgs(args)
    
	if err != nil {
        utils.Abort(fmt.Sprintf("Unable to create argument parser: %v", err))
    }
    
	return &opts
}