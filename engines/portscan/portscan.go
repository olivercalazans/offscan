package portscan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"offscan/conv"
	"offscan/dissectors"
	"offscan/generators"
	"offscan/ifaceinfo"
	"offscan/packet"
	"offscan/pktsniff"
	"offscan/sockets"
	"offscan/sysinfo"
	"offscan/utils"
)



type PortScanner struct {
    iface      *net.Interface
    myIP        net.IP
    targetIP    net.IP
    ports      *string
    random      bool
    delay       string
    udp         bool
    openPorts   map[uint16]bool
    mut         sync.Mutex
    cancel      context.CancelFunc 
    wg          sync.WaitGroup
}



func New(argList []string) *PortScanner {
	args  := ParsePortScanArgs(argList)
	dstIP := conv.MustStrToIPv4(args.TargetIP)
	iface := sysinfo.MustRouteIfaceForDstIP(dstIP)
	myIP  := ifaceinfo.MustIPv4(iface)
    
    return &PortScanner{
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



func (ps *PortScanner) Execute() {
    ps.displayInfo()
    ps.startPacketProcessor()
    ps.sendProbes()
    ps.stopPacketProcessor()
    ps.displayResult()
}



func (ps *PortScanner) displayInfo() {
    proto := "TCP"

	if ps.udp {
        proto = "UDP"
    }

	fmt.Printf("[*] Iface...: %s\n", ps.iface.Name)
    fmt.Printf("[*] Target..: %s\n", ps.targetIP.String())
    fmt.Printf("[*] Proto...: %s\n", proto)
}



func (ps *PortScanner) startPacketProcessor() {
    sniffer  := pktsniff.NewSniffer(ps.iface, ps.getBPFFilter(), false)
    packetCh := sniffer.Start()

    ctx, cancel := context.WithCancel(context.Background())
    ps.cancel    = cancel

    ps.wg.Add(1)
    go func() {
        defer ps.wg.Done()
        tempPorts := make(map[uint16]bool)
        dissector := dissectors.NewPacketDissector()

        for {
            select {
            case <-ctx.Done():
                sniffer.Stop()
                ps.mut.Lock()
            
				for p := range tempPorts {
                    ps.openPorts[p] = true
                }
            
				ps.mut.Unlock()
                return
            
			case pkt, ok := <-packetCh:
                if !ok {
                    return
                }
                ps.dissectAndUpdate(dissector, tempPorts, pkt)
            }
        }
    }()
}



func (ps *PortScanner) getBPFFilter() string {
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



func (ps *PortScanner) dissectAndUpdate(dissector *dissectors.PacketDissector, tempPorts map[uint16]bool, pkt []byte) {
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



func (ps *PortScanner) stopPacketProcessor() {
    if ps.cancel != nil {
        ps.cancel()
    }
    ps.wg.Wait()
}


func (ps *PortScanner) sendProbes() {
    socket  := sockets.NewL3Socket(ps.iface)
    randGen := generators.NewRandomValues(nil, nil)

    if ps.udp {
        ps.sendUdpProbes(socket, randGen)
    } else {
        ps.sendTcpProbes(socket, randGen)
    }

    time.Sleep(3 * time.Second)
}



func (ps *PortScanner) sendTcpProbes(socket *sockets.Layer3Socket, randGen *generators.RandomValues) {
    portIter  := generators.NewPortIter(ps.ports, ps.random)
    delayIter := generators.NewDelayIter(ps.delay, portIter.Len())
    builder   := packet.NewTcpPkt()

    for {
        port, ok := portIter.Next()
        if !ok {
            break
        }
        
		delay, ok := delayIter.Next()
        if !ok {
            break
        }
        
		srcPort := randGen.RandomPort()
        pkt     := builder.L3Pkt(ps.myIP, srcPort, ps.targetIP, port)
        
		socket.SendTo(pkt, ps.targetIP)
        time.Sleep(time.Duration(float64(delay) * float64(time.Second)))
    }
}



func (ps *PortScanner) sendUdpProbes(socket *sockets.Layer3Socket, randGen *generators.RandomValues) {
    payloads  := packet.NewUdpPayloads(ps.myIP)
    entries   := payloads.Entries()
    delayIter := generators.NewDelayIter(ps.delay, len(entries))
    builder   := packet.NewUdpPkt()

    for _, entry := range entries {
        delay, ok := delayIter.Next()
        if !ok {
            break
        }
        srcPort := randGen.RandomPort()
        pkt := builder.L3Pkt(ps.myIP, srcPort, ps.targetIP, entry.Port, entry.Payload)
        socket.SendTo(pkt, ps.targetIP)
        time.Sleep(time.Duration(float64(delay) * float64(time.Second)))
    }
}



func (ps *PortScanner) displayResult() {
    deviceName := utils.GetHostName(ps.targetIP.String())
    ports      := ps.formatPorts()
    
	fmt.Printf("\nOpen ports from %s (%s)\n", deviceName, ps.targetIP.String())
    fmt.Println(ports)
}



func (ps *PortScanner) formatPorts() string {
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