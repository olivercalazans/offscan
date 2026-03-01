package beacon

import (
	"fmt"
	"net"
	"offscan/conv"
	"offscan/utils"

	"github.com/jessevdk/go-flags"
)



type BcFloodArgs struct {
	Ssid    string
	Iface   *net.Interface
	Channel int
}



type Args struct {
    Ssid    string `short:"s" long:"ssid" description:"SSID/Network name" required:"true"`
    Iface   string `short:"i" long:"iface" description:"Interface to be used" required:"true"`
    Channel int    `short:"c" long:"channel" description:"Channel" required:"true"`
}



func parseArgs(args []string) *BcFloodArgs {
    var opts Args

	parser := flags.NewParser(&opts, flags.None)
    _, err := parser.ParseArgs(args)

	if err != nil {
        utils.Abort(fmt.Sprintf("failed to parse arguments: %v", err))
    }

	bcArgs := &BcFloodArgs{
		Ssid:    opts.Ssid,
		Iface:   conv.MustGetIface(opts.Iface),
		Channel: opts.Channel,
	}

	return bcArgs
}