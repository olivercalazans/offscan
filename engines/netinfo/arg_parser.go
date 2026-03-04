package netinfo

import (
	"fmt"
	"offscan/utils"
	"os"

	"github.com/jessevdk/go-flags"
)



type NetInfoArgs struct {
    Iface string `short:"i" long:"iface" description:"Define a network interface to get information (optional)" value-name:"IFACE"`
}



func ParseNetInfoArgs(argList []string) *NetInfoArgs {
    var opts NetInfoArgs

	parser := flags.NewParser(&opts, flags.HelpFlag)
    _, err := parser.ParseArgs(argList)

	if err != nil {
		if flags.WroteHelp(err) {
			fmt.Printf("%v", err)
			os.Exit(0)
		}
		
        utils.Abort(fmt.Sprintf("Unable to create argument parser: %v", err))
    }

	return &opts
}