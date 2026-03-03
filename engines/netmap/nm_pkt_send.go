package netmap

import (
	"fmt"
	"offscan/generators"
	"offscan/packet"
	"offscan/sockets"
	"offscan/utils"
	"time"
)



func (nm *NetworkMapper) createGoroutines() {
    if nm.icmp {
        nm.wg.Add(1)
        go nm.sendProbes("icmp", *nm.ips)
    }
    
	if nm.tcp {
        nm.wg.Add(1)
        go nm.sendProbes("tcp", *nm.ips)
    }
    
	if nm.udp {
        nm.wg.Add(1)
        go nm.sendProbes("udp", *nm.ips)
    }

    nm.wg.Wait()
    time.Sleep(3 * time.Second)
}



func (nm *NetworkMapper) sendProbes(proto string, ips generators.Ipv4Iter) {
    defer nm.wg.Done()

    delays  := generators.NewDelayIter(nm.delay, int(ips.Total()))
    randGen := generators.NewRandomValues(nil, nil)
    socket  := sockets.NewL3Socket(nm.iface)

    icmpPkt := packet.NewIcmpPkt()
    tcpPkt  := packet.NewTcpPkt()
    udpPkt  := packet.NewUdpPkt()

    for {
        dstIP, ok := ips.Next()
        if !ok {
            break
        }
        
		delay, ok := delays.Next()
        if !ok {
            break
        }

        var pkt []byte
        
		switch proto {
        case "icmp":
            pkt = icmpPkt.L3Pkt(nm.myIP, dstIP)
        
		case "tcp":
            srcPort := randGen.RandomPort()
            pkt = tcpPkt.L3Pkt(nm.myIP, srcPort, dstIP, 80)
        
		case "udp":
            srcPort := randGen.RandomPort()
            pkt = udpPkt.L3Pkt(nm.myIP, srcPort, dstIP, 53, []byte{})
        
		default:
            utils.Abort(fmt.Sprintf("Unknown protocol: %s", proto))
        }

        socket.SendTo(pkt, dstIP)
        time.Sleep(time.Duration(delay * float64(time.Second)))
    }
}