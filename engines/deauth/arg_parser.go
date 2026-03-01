package deauth

import (
	"fmt"
	"net"
	"offscan/conv"
	"offscan/utils"

	"github.com/jessevdk/go-flags"
)



type DeauthArgs struct {
    Iface     *net.Interface 
    TargetMac  net.HardwareAddr
    Bssid      net.HardwareAddr
    Delay      int
    Channel    int
}


type Args struct {
    Iface     string `short:"i" long:"iface" description:"Network interface" required:"true"`
    TargetMac string `short:"t" long:"target-mac" description:"Target MAC" required:"true"`
    Bssid     string `short:"b" long:"bssid" description:"BSSID" required:"true"`
    Delay     int    `short:"d" long:"delay" default:"30" description:"Delay in ms"`
    Channel   int    `short:"c" long:"channel" description:"Channel" required:"true"`
}



func ParseArgs(args []string) *DeauthArgs {
    var opts Args
    
    parser := flags.NewParser(&opts, flags.None)
    _, err := parser.ParseArgs(args)
    
    if err != nil {
        utils.Abort(fmt.Sprintf("Unable to create the deauth argument parser: %v", err))
    }

    deauthArgs := &DeauthArgs{
        Delay:     opts.Delay,
        Channel:   opts.Channel,
        Iface:     conv.MustGetIface(opts.Iface),
        Bssid:     conv.MustStrToMac(opts.Bssid),
        TargetMac: conv.MustStrToMac(opts.TargetMac),
    }
    
    return deauthArgs
}