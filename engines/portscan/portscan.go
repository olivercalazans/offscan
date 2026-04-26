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

package portscan

import (
	"fmt"
	"maps"
	"net"
	"strings"
	"sync"
	"time"

	"offscan/internal/conv"
	"offscan/internal/generators"
	"offscan/internal/ifaceinfo"
	"offscan/internal/netroute"
	"offscan/internal/pktbuilder"
	"offscan/internal/pktdissector"
	"offscan/internal/pktsniffer"
	"offscan/internal/sockets"
	"offscan/internal/sysinfo"
)



func Run(args []string) {
    newPortScanner(args).execute()
}



type portScanner struct {
    iface      *net.Interface
    myIP        net.IP
    targetIP    net.IP
    ports      *string
    random      bool
    delay       string
    udp         bool
    openPorts   map[uint16]bool
    mut         sync.Mutex
    wg          sync.WaitGroup
    sniffer    *pktsniffer.Sniffer
}



func newPortScanner(argList []string) *portScanner {
	args  := parsePortScanArgs(argList)
	dstIP := conv.MustStrToIPv4(args.TargetIP)
	iface := netroute.MustRouteIfaceForDstIP(dstIP)
	myIP  := ifaceinfo.MustIPv4(iface)
    
    return &portScanner{
        iface:      iface,
        myIP:       myIP,
        targetIP:   dstIP,
        ports:      args.Ports,
        random:     args.Random,
        delay:      args.Delay,
        udp:        args.UDP,
        openPorts:  make(map[uint16]bool),
    }
}



func (ps *portScanner) execute() {
    ps.displayInfo()
    ps.startPacketProcessor()
    ps.sendTcpProbes()
    ps.stopPacketProcessor()
    ps.displayResult()
}



func (ps *portScanner) displayInfo() {
    proto := "TCP"

	if ps.udp {
        proto = "UDP"
    }

	fmt.Printf("[*] Iface...: %s\n", ps.iface.Name)
    fmt.Printf("[*] Target..: %s\n", ps.targetIP.String())
    fmt.Printf("[*] Proto...: %s\n", proto)
}



func (ps *portScanner) startPacketProcessor() {
    ps.sniffer = pktsniffer.NewSniffer(ps.iface, ps.getBPFFilter(), false)
    packetCh  := ps.sniffer.Start()

    ps.wg.Add(1)
    go func() {
        defer ps.wg.Done()
        
        tempPorts := make(map[uint16]bool)
        dissector := pktdissector.NewPacketDissector()

        for {
			pkt, ok := <-packetCh
            if !ok { break }
            ps.dissectAndUpdate(dissector, tempPorts, pkt)
        }

        ps.mut.Lock()
        maps.Copy(ps.openPorts, tempPorts)
		ps.mut.Unlock()
    }()
}



func (ps *portScanner) getBPFFilter() string {
    if ps.udp {
        return fmt.Sprintf(
			"udp and dst host %s and src host %s",
            ps.myIP.String(), ps.targetIP.String(),
		)
    }

	return fmt.Sprintf(
		"tcp[13] & 0x12 == 0x12 and dst host %s and src host %s",
        ps.myIP.String(), ps.targetIP.String(),
	)
}



func (ps *portScanner) dissectAndUpdate(dissector *pktdissector.PacketDissector, tempPorts map[uint16]bool, pkt []byte) {
    dissector.UpdatePkt(pkt)
    var port uint16
    var ok bool

	if ps.udp {
        port, ok = dissector.GetUDPSrcPort()
    } else {
        port, ok = dissector.GetTCPSrcPort()
    }

	if ok {
        tempPorts[port] = true
    }
}



func (ps *portScanner) stopPacketProcessor() {
    ps.sniffer.Stop()
    ps.wg.Wait()
}



func (ps *portScanner) sendTcpProbes() {
    socket    := sockets.NewL3Socket(ps.iface)
    randGen   := generators.NewRandomValues()
    portIter  := generators.NewPortIter(ps.ports, ps.random)
    delayIter := generators.NewDelayIter(ps.delay, portIter.Len())

    for {
        port, ok := portIter.Next()
        if !ok { break }
        
		delay, ok := delayIter.Next()
        if !ok { break }
        
		srcPort := randGen.RandomPort()
     
        if pkt, err := pktbuilder.TcpSynPkt(ps.myIP, ps.targetIP, srcPort, port); err == nil {
            socket.SendTo(pkt, ps.targetIP)
            time.Sleep(time.Duration(float64(delay) * float64(time.Second)))
        }
    }

    time.Sleep(3 * time.Second)
}



func (ps *portScanner) displayResult() {
    deviceName := sysinfo.GetHostName(ps.targetIP.String())
    ports      := ps.formatPorts()
    
	fmt.Printf("\nOpen ports from %s (%s)\n", deviceName, ps.targetIP.String())
    fmt.Println(ports)
}



func (ps *portScanner) formatPorts() string {
    ps.mut.Lock()
    defer ps.mut.Unlock()

	if len(ps.openPorts) == 0 {
        return "None"
    }

	var ports []string
    for p := range ps.openPorts {
        ports = append(ports, fmt.Sprintf("%d", p))
    }

	return strings.Join(ports, ", ")
}