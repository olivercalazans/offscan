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
	"fmt"
	"maps"
	"net"
	"offscan/internal/conv"
	"offscan/internal/frame80211/dissector"
	"offscan/internal/ifconfig"
	"offscan/internal/sniffer"
	"sync"
	"time"
)



func Run(args []string) {
    newL2Disc(args).execute()
}



type layer2HostDiscovery struct{
	iface      net.Interface
	nets       map[beaconInfo]struct{}
	stations   map[dataFrameInfo]struct{}
	sniffer   *sniffer.Sniffer
	mut        sync.Mutex
	wg         sync.WaitGroup
}



func newL2Disc(args []string) *layer2HostDiscovery {
	parser := newParser()
	parser.parseL2DiscArgs(args)

	return &layer2HostDiscovery{
		iface    : parser.Iface,
		nets     : make(map[beaconInfo]struct{}),
	    stations : make(map[dataFrameInfo]struct{}),
	}
}



func (l2hd *layer2HostDiscovery) execute() {
	l2hd.startFrameProcessor()
	l2hd.sniff2GChannels()
	l2hd.sniff5GChannels()
	l2hd.stopFrameProcessor()
	l2hd.displayResults()
}



func (l2hd *layer2HostDiscovery) startFrameProcessor() {
	l2hd.sniffer  = sniffer.NewSniffer(l2hd.iface, getBPFFilter(), true)
	sniffCh      := l2hd.sniffer.Start()

	fmt.Printf("[+] Sniffing 802.11 frames\n")

	l2hd.wg.Add(1)
	go func() {
		defer l2hd.wg.Done()
		l2hd.processFrame(sniffCh)
	}()
}



func getBPFFilter() string {
	return "(wlan type mgt and wlan subtype beacon) or wlan type data"
}



func (l2hd *layer2HostDiscovery) processFrame(sniffCh <-chan []byte) {
	tools := dissecAndBufs{
		staBuf    : make(map[dataFrameInfo]struct{}),
		netsBuf   : make(map[beaconInfo]struct{}),
		dissector : dissector.NewDot11Dissector(),
	}

	for {
		frame, ok := <-sniffCh
		if !ok { break }
		tools.dissector.UpdatePkt(frame)
		l2hd.updateInfo(&tools)
	}

	l2hd.mut.Lock()
	maps.Copy(l2hd.stations, tools.staBuf)
	maps.Copy(l2hd.nets, tools.netsBuf)
	l2hd.mut.Unlock()
}



func (l2hd *layer2HostDiscovery) updateInfo(tools *dissecAndBufs) {
	if tools.dissector.IsBeacon {
		ap := beaconInfo{
			ssid  : tools.dissector.GetSSID(),
			bssid : tools.dissector.GetBSSID(),
			chnl  : tools.dissector.GetChannel(),
		}

		tools.netsBuf[ap] = struct{}{}
	}

	if tools.dissector.IsDataFrm {
		bssid, staMac, ok := tools.dissector.GetAddrs()
		if !ok { return }
		sta := dataFrameInfo{ bssid: bssid, staMac: staMac }
		tools.staBuf[sta] = struct{}{}
	}
}



func (l2hd *layer2HostDiscovery) sniff2GChannels() {
	channels := ifconfig.Channels2()
	l2hd.sniffChannels(channels, "2.4")
}



func (l2hd *layer2HostDiscovery) sniff5GChannels() {
	channels := ifconfig.Channels5()
	l2hd.sniffChannels(channels, "5")
}



func (l2hd *layer2HostDiscovery) sniffChannels(channels []int, freq string) {
	var errChannels []int

	for _, chnl := range channels {
		ok := ifconfig.TrySetChannel(l2hd.iface, chnl)

		if ok != nil {
			errChannels = append(errChannels, chnl)
			continue
		}

		time.Sleep(1 * time.Second)
	}

	if len(errChannels) > 0 {
		fmt.Printf("[!] Unable to sniff these channels (%sG):\n%v\n", freq, errChannels)
	}
}



func (l2hd *layer2HostDiscovery) stopFrameProcessor() {
	l2hd.sniffer.Stop()
	fmt.Println("[-] Sniffer stopped")
	l2hd.wg.Wait()
}



func (l2hd *layer2HostDiscovery) displayResults() {
	nets, maxLen := l2hd.extractKeysAndMaxLen()

	for _, net := range nets {
		l2hd.displayStation(&net, maxLen)
	}
}



func (l2hd *layer2HostDiscovery) extractKeysAndMaxLen() ([]beaconInfo, int) {
	maxLen := 4
	keys   := make([]beaconInfo, 0, len(l2hd.nets))
	
	for netData := range l2hd.nets {
		keys = append(keys, netData)

        if len(netData.ssid) > maxLen {
			maxLen = len(netData.ssid)
		}
	}

    return keys, maxLen
}



func (l2hd *layer2HostDiscovery) displayStation(net *beaconInfo, maxLen int) {
	for sta := range l2hd.stations {
		if sta.bssid != net.bssid {	continue }

		
		fmt.Printf(
			"%-*s  %-3d  %s  %s\n", 
			maxLen, net.ssid, net.chnl,
			conv.Byte6ToStr(net.bssid), 
			conv.Byte6ToStr(sta.staMac),
		)
		
		delete(l2hd.stations, sta)
		return
	}
}