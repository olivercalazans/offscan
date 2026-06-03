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
	"net"
	"offscan/internal/frame80211/dissector"
	"offscan/internal/sniffer"
	"sync"
)



func Run(args []string) {
    newL2Disc(args).execute()
}



type layer2HostDiscovery struct{
	iface      net.Interface
	stations   map[dataFrameInfo]struct{}
	aps        map[apInfo]struct{}
	sniffer   *sniffer.Sniffer
	wg         sync.WaitGroup
}


type dataFrameInfo struct {
	apMac   [6]byte
	staMac  [6]byte
}


type beaconInfo struct {
	bssid  [6]byte
	ssid   string
	chnl   uint8
}



func newL2Disc(args []string) *layer2HostDiscovery {
	parser := newParser()
	parser.parseL2DiscArgs(args)

	return &layer2HostDiscovery{
		iface : parser.Iface,
	}
}



func (l2hd *layer2HostDiscovery) execute() {
	l2hd.startFrameProcessor()
}



func (l2hd *layer2HostDiscovery) startFrameProcessor() {
	l2hd.sniffer = sniffer.NewSniffer(l2hd.iface, getBPFFilter(), true)
	sniffCh      := l2hd.sniffer.Start()

	fmt.Printf("[+] Sniffing frames 802.11\n")

	l2hd.wg.Add(1)
	go func() {
		defer l2hd.wg.Done()
		l2hd.processFrame(sniffCh)
	}()
}



func getBPFFilter() string {
	return "wlan type mgt subtype beacon or wlan type data"
}



func (l2hd *layer2HostDiscovery) processFrame() {
	stationBuf := make(map[dataFrameInfo]struct{})
	apBuf      := make(map[apInfo]struct{})
	dissector  := 
}