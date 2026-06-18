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

package l2disc

import (
	"context"
	"fmt"
	"maps"
	"math"
	"net"
	"offscan/internal/sniffer"
	"offscan/internal/sysconf"
	"os"
	"os/signal"
	"slices"
	"sync"
	"syscall"
	"time"
)



func Run(args []string) {
    newL2Disc(args).execute()
}



type layer2HostDiscovery struct{
	iface       net.Interface
	sniffTime   time.Duration
	sniffer    *sniffer.Sniffer
	wg          sync.WaitGroup
	eventCh     chan dot11Info
	ctx         context.Context
	cancel      context.CancelFunc
	errChnls    map[int]struct{}
}



func newL2Disc(args []string) *layer2HostDiscovery {
	parser := newParser()
	parser.parseL2DiscArgs(args)

	return &layer2HostDiscovery{
		iface     : parser.Iface,
		sniffTime : calculateDuration(parser.sniffTime),
		errChnls  : make(map[int]struct{}),
	}
}



func calculateDuration(sniffTime float64) time.Duration {
	nano := math.Round(sniffTime * float64(time.Second))
	return time.Duration(nano)
}



func (l2hd *layer2HostDiscovery) execute() {
	l2hd.displayExecInfo()
	l2hd.createCtx()
	l2hd.startFrameProcessor()
	l2hd.sniffEndlessly()
	l2hd.stopFrameProcessor()
}



func (l2hd *layer2HostDiscovery) displayExecInfo() {
	fmt.Printf("[i] IFACE: %s\n", l2hd.iface.Name)
	fmt.Printf("[i] DELAY: %.2fs\n", l2hd.sniffTime.Seconds())
}



func (l2hd *layer2HostDiscovery) createCtx() {
    l2hd.ctx, l2hd.cancel = context.WithCancel(context.Background())

	go func() {
        sigCh := make(chan os.Signal, 1)
        signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
        <-sigCh
        fmt.Println("\n[!] Interrupt received. Stopping...")
        l2hd.cancel()
    }()
}



func (l2hd *layer2HostDiscovery) startFrameProcessor() {
	l2hd.eventCh = make(chan dot11Info, 1024)
    go l2hd.displayLoop()

	l2hd.sniffer  = sniffer.NewSniffer(l2hd.iface, getBPFFilter(), true)
	sniffCh      := l2hd.sniffer.Start()

	fmt.Printf("[+] Sniffing 802.11 frames. Press CTRL + C to stop\n")

	l2hd.wg.Add(1)
	go func() {
		defer l2hd.wg.Done()
		l2hd.processFrame(sniffCh)
	}()

	displayHeader()
}



func getBPFFilter() string {
	return "(wlan type mgt and wlan subtype beacon) or wlan type data"
}



func (l2hd *layer2HostDiscovery) sniffEndlessly() {
    for {
        select {
        case <-l2hd.ctx.Done():
            return

		default:
        }

        l2hd.sniff2GChannels()
        l2hd.sniff5GChannels()

		if l2hd.ctx.Err() != nil { return }
    }
}



func (l2hd *layer2HostDiscovery) sniff2GChannels() {
	channels := sysconf.Channels2()
	l2hd.sniff(channels)
}



func (l2hd *layer2HostDiscovery) sniff5GChannels() {
	channels := sysconf.Channels5()
	l2hd.sniff(channels)
}



func (l2hd *layer2HostDiscovery) sniff(channels []int) {
    for _, chnl := range channels {
        if l2hd.ctx.Err() != nil { return }
        
		ok := sysconf.TrySetChannel(l2hd.iface, chnl)
        if ok != nil {
            l2hd.errChnls[chnl] = struct{}{}
            continue
        }

		select {
        case <-time.After(l2hd.sniffTime):
        case <-l2hd.ctx.Done(): return }
    }
}



func (l2hd *layer2HostDiscovery) stopFrameProcessor() {
	l2hd.sniffer.Stop()
	close(l2hd.eventCh)
	
	fmt.Println("[-] Process stopped")
	l2hd.displayErrChannels()
	l2hd.wg.Wait()
}



func (l2hd *layer2HostDiscovery) displayErrChannels() {
	if len(l2hd.errChnls) == 0 { return }
	chnls := slices.Collect(maps.Keys(l2hd.errChnls))
	fmt.Printf("[!] Unable to sniff these channels: %v\n", chnls)
}