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

	"offscan/internal/generators"
	"offscan/internal/netroute"
	"offscan/internal/pktbuild"
	"offscan/internal/pktdissec"
	"offscan/internal/sniffer"
	"offscan/internal/sockets"
	"offscan/internal/utils"
)



func Run(args []string) {
    ps := portScanner{}
    ps.parseArgs(args)
    ps.execute()
}


const delay = 30 * time.Millisecond


type portScanner struct {
    iface       net.Interface
    myIP        net.IP
    targetIP    net.IP
    ports       string
    random      bool
    openPorts   map[uint16]struct{}
    mut         sync.Mutex
    wg          sync.WaitGroup
    sniffer    *sniffer.Sniffer
}



func (ps *portScanner) execute() {
    ps.displayInfo()
    ps.startPacketProcessor()
    ps.sendTcpProbes()
    ps.stopPacketProcessor()
    ps.displayResult()
}



func (ps *portScanner) displayInfo() {
    var scan string
    if ps.random { scan = "Random" } else { scan = "Serial" }

	fmt.Printf("[i] Iface...: %s\n", ps.iface.Name)
    fmt.Printf("[i] Target..: %s\n", ps.targetIP.String())
    fmt.Printf("[i] Proto...: TCP (%s)\n", scan)
}



func (ps *portScanner) startPacketProcessor() {
    ps.sniffer = sniffer.NewSniffer(ps.iface, ps.getBPFFilter(), false)
    packetCh  := ps.sniffer.Start()

    ps.wg.Add(1)
    go func() {
        defer ps.wg.Done()
        
        tempPorts := make(map[uint16]struct{})
        dissector := pktdissec.NewPacketDissector()

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
	return fmt.Sprintf(
		"tcp[13] & 0x12 == 0x12 and dst host %s and src host %s",
        ps.myIP.String(), ps.targetIP.String(),
	)
}



func (ps *portScanner) dissectAndUpdate(
    dissector  *pktdissec.PacketDissector, 
    tempPorts   map[uint16]struct{}, 
    pkt         []byte,
) {
    dissector.UpdatePkt(pkt)
    if !dissector.IsIPv4() { return }

    if port, ok := dissector.GetTcpSrcPort(); ok {
        tempPorts[port] = struct{}{}
    }
}



func (ps *portScanner) stopPacketProcessor() {
    ps.sniffer.Stop()
    ps.wg.Wait()
}



func (ps *portScanner) sendTcpProbes() {
    builder  := pktbuild.NewTcpPkt()
    socket   := sockets.NewL3Socket(&ps.iface)
    randGen  := generators.NewRandomValues()
    portIter := generators.NewPortIter(ps.ports, ps.random)

    for {
        port, hasPort := portIter.Next()
        
        if !hasPort { break }
        
        builder.IPHdr.SetSrcIP(ps.myIP)
        builder.IPHdr.SetDstIP(ps.targetIP)
        builder.SetSrcPort(randGen.RandomPort())
        builder.SetDstPort(port)
        
        pkt := builder.Pkt()
        
        socket.SendTo(pkt, ps.targetIP)
        time.Sleep(delay)
    }

    ps.closeSocket(&socket)
    time.Sleep(3 * time.Second)
}



func (ps *portScanner) closeSocket(socket *sockets.Layer3Socket) {
    if err := socket.Close(); err != nil {
        fmt.Printf("[!] Error closing socket: %v\n", err)
    }
}



func (ps *portScanner) displayResult() {
    deviceName := netroute.GetHostName(ps.targetIP.String())    
	fmt.Printf("\nOpen ports from %s (%s)\n", deviceName, ps.targetIP.String())
    ps.formatPorts()
}



func (ps *portScanner) formatPorts() {
    ps.mut.Lock()
    defer ps.mut.Unlock()

    if len(ps.openPorts) == 0 {
        fmt.Println("None")
        return
    }
    
    portsSlice := utils.SortKeys(ps.openPorts)

    portsStr := make([]string, len(portsSlice))
    for i, p := range portsSlice {
        portsStr[i] = fmt.Sprintf("%d", p)
    }

    fmt.Println(strings.Join(portsStr, ", "))
}