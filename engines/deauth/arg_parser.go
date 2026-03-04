package deauth

import (
	"fmt"
	"net"
	"offscan/conv"
	"offscan/utils"
	"os"

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
    TargetMac string `short:"t" long:"tmac" description:"Target MAC" required:"true"`
    Bssid     string `short:"b" long:"bssid" description:"BSSID" required:"true"`
    Delay     int    `short:"d" long:"delay" default:"30" description:"Delay in ms"`
    Channel   int    `short:"c" long:"channel" description:"Channel" required:"true"`
}



func ParseArgs(argList []string) *DeauthArgs {
    var opts Args
    
    parser := flags.NewParser(&opts, flags.HelpFlag)
    _, err := parser.ParseArgs(argList)
    
    if err != nil {
        if flags.WroteHelp(err) {
			fmt.Printf("%v", err)
			os.Exit(0)
		}
        
        utils.Abort(fmt.Sprintf("Unable to create argument parser: %v", err))
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