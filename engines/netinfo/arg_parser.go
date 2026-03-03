package netinfo

import (
	"fmt"
	"offscan/utils"

	"github.com/jessevdk/go-flags"
)



type NetInfoArgs struct {
    Iface string `short:"i" long:"iface" description:"Define a network interface to get information (optional)" value-name:"IFACE"`
}



func ParseNetInfoArgs(argList []string) *NetInfoArgs {
    var opts NetInfoArgs

	parser := flags.NewParser(&opts, flags.None)
    _, err := parser.ParseArgs(argList)

	if err != nil {
        utils.Abort(fmt.Sprintf("Unable to create argument parser: %v", err))
    }

	return &opts
}