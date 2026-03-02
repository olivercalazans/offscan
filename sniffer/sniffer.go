package sniffer

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"offscan/utils"
)


type Sniffer struct {
    iface     *net.Interface
    filter     string
    promisc    bool
    stopChan   chan struct{}
    resultCh   chan []byte
    wg         sync.WaitGroup
    stats      pcap.Stats
}



func NewSniffer(iface *net.Interface, filter string, promisc bool) *Sniffer {
    return &Sniffer{
        iface    : iface,
        filter   : filter,
        promisc  : promisc,
        stopChan : make(chan struct{}),
        resultCh : make(chan []byte, 100),
    }
}



func (s *Sniffer) Start() <-chan []byte {
    s.wg.Add(1)
    go s.captureLoop()
    return s.resultCh
}



func (s *Sniffer) captureLoop() {
    defer s.wg.Done()
    defer close(s.resultCh)

    handle, err := pcap.OpenLive(s.iface.Name, 65536, s.promisc, 100 * time.Millisecond)

	if err != nil {
        utils.Abort(fmt.Sprintf("Failed to open interface %s: %v", s.iface.Name, err))
    }
    defer handle.Close()

    if err := handle.SetBPFFilter(s.filter); err != nil {
        utils.Abort(fmt.Sprintf("Failed to set filter: %v", err))
    }

    source := gopacket.NewPacketSource(handle, handle.LinkType())

    for {
        select {
        
		case <-s.stopChan:
            statsPtr, err := handle.Stats()
            if err == nil {
                s.stats = *statsPtr
            }
            return
        
		default:
            packet, err := source.NextPacket()

			if err != nil {
                continue
            }

			select {
            	case s.resultCh <- packet.Data():
				case <-s.stopChan: return
            }
        }
    }
}



func (s *Sniffer) Stop() {
    close(s.stopChan)
    s.wg.Wait()

	fmt.Printf(
        "[$] Packets received = %d, dropped = %d, if_dropped = %d\n",
        s.stats.PacketsReceived, s.stats.PacketsDropped, s.stats.PacketsIfDropped,
    )
}