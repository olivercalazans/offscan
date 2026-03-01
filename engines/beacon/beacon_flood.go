package beacon

import (
	"fmt"
	"net"
	"time"

	"offscan/frame80211"
	"offscan/generators"
	"offscan/ifconfig"
	"offscan/sockets"
	"offscan/utils"
)



type BeaconFlood struct {
    channel uint8
    ssid    string
    bcSent  int
    builder *frame80211.Beacon
    socket  *sockets.Layer2Socket
}



func New(args []string) *BeaconFlood {
	bcArgs := parseArgs(args)

    ifconfig.MustSetChannel(bcArgs.Iface, bcArgs.Channel)

    return &BeaconFlood{
        channel: uint8(bcArgs.Channel),
        ssid:    bcArgs.Ssid,
        bcSent:  0,
        builder: frame80211.NewBeacon(),
        socket:  sockets.NewL2Socket(bcArgs.Iface),
    }
}



func (b *BeaconFlood) Execute() {
    ctx     := utils.SignalContext()
    randGen := generators.NewRandomValues(nil, nil)
    start   := time.Now()
    
	fmt.Println("[+] Sending beacons. Press Ctrl+C to stop")

    for {
        select {
        case <-ctx.Done():
            elapsed := time.Since(start).Seconds()
            fmt.Printf("\n[-] Flood interrupted\n")
            fmt.Printf("[%%] %d beacons sent in %.2f seconds\n", b.bcSent, elapsed)
            return

        default:
            bssid := randGen.RandomMac()
            ssid  := randGen.RandomCaseInversion(b.ssid)
            seq   := randGen.RandomSeq()
            b.sendQuartet(bssid, ssid, seq)
        }
    }
}



func (b *BeaconFlood) sendQuartet(bssid net.HardwareAddr, ssid string, seq uint16) {
    b.sendBeacon(bssid, ssid, seq, "open")
    b.sendBeacon(bssid, ssid, seq+1, "wpa")
    b.sendBeacon(bssid, ssid, seq+2, "wpa2")
    b.sendBeacon(bssid, ssid, seq+3, "wpa3")
}



func (b *BeaconFlood) sendBeacon(bssid net.HardwareAddr, ssid string, seq uint16, sec string) {
    beacon := b.builder.Beacon(bssid, ssid, seq, b.channel, sec)
    b.socket.Send(beacon)
    b.bcSent++
}