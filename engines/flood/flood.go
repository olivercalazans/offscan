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

package flood

import (
	"fmt"
	"net"

	"offscan/internal/conv"
	"offscan/internal/generators"
	"offscan/internal/ifaceinfo"
	"offscan/internal/netroute"
	"offscan/internal/sysinfo"
	"offscan/internal/utils"
)



func Run(args []string) {
    newFlooder(args).execute()
}



type flooder struct {
    iface     *net.Interface
    pktsSent   int
    rand      *generators.RandomValues
    srcIP      net.IP
    srcMAC     net.HardwareAddr
    dstIP      net.IP
    dstMAC     net.HardwareAddr
    dstPort    uint16
	protocol   string
    duration   float64
}



func newFlooder(argList []string) *flooder {
    args := parseFloodArgs(argList)

	if !args.Icmp && !args.Tcp {
		utils.Abort("No protocol selected")
	}

	proto := "ICMP"
	if args.Tcp { proto = "TCP" }

	dstIP  := conv.MustStrToIPv4(args.DstIP)
	dstMAC := conv.MustStrToMac(args.DstMAC)

	iface  := netroute.MustRouteIfaceForDstIP(dstIP)
    cidr   := ifaceinfo.MustCIDR(iface)
	
	srcIP  := net.ParseIP(args.SrcIP)
	srcMAC := sysinfo.ResolveMac(args.SrcMAC, iface)

    firstIP, lastIP := utils.GetFirstAndLastIP(cidr)
	
	randGen := generators.NewRandomValues(&firstIP, &lastIP)

    return &flooder{
        iface:     iface,
        rand:      randGen,
        srcIP:     srcIP,
        srcMAC:    srcMAC,
        dstIP:     dstIP,
        dstMAC:    dstMAC,
        dstPort:   args.Port,
		protocol:  proto,
    }
}



func (f *flooder) execute() {
    f.displayInfo()
    f.sendEndlessly()
    f.displayExecInfo()
}



func (f *flooder) displayInfo() {
    srcMACStr := "Random"
    if f.srcMAC != nil {
        srcMACStr = f.srcMAC.String()
    }

	srcIPStr := "Random"
    if f.srcIP != nil {
        srcIPStr = f.srcIP.String()
    }

	fmt.Printf("[*] PROTOCOL..: %s\n", f.protocol)
	fmt.Printf("[*] SRC >> MAC: %s / IP: %s\n", srcMACStr, srcIPStr)
    fmt.Printf("[*] DST >> MAC: %s / IP: %s\n", f.dstMAC.String(), f.dstIP.String())
    fmt.Printf("[*] IFACE.....: %s\n", f.iface.Name)
}



func (f *flooder) sendEndlessly() {
	switch f.protocol {
	case "ICMP": f.sendPingEndlessly()
	case "TCP":  f.sendTcpEndlessly()
	}
}




func (f *flooder) displayExecInfo() {
    fmt.Printf("[%%] %d packets sent in %.2f seconds\n", f.pktsSent, f.duration)

    if f.duration > 1.0 {
        rate := float64(f.pktsSent) / f.duration
        fmt.Printf("[%%] %.2f packets sent per second\n", rate)
    }
}