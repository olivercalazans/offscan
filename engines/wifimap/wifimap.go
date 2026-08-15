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

package wifimap

import (
	"fmt"
	"net"
	"offscan/internal/conv"
	"offscan/internal/dot11dissec"
	"offscan/internal/sniffer"
	"offscan/internal/sysconf"
	"slices"
	"strings"
	"sync"
	"time"
)


func Run(args []string) {
	wm := wifiMapper{}
	wm.parseArgs(args)
	wm.execute()
}



type wifiMapper struct {
	iface     net.Interface
	wInfo     map[wifiData]struct{}
	sniffer  *sniffer.Sniffer
	dataCh    chan map[wifiData]struct{}
	wg        sync.WaitGroup
	cancel    chan struct{}
	maxLen    maxLength
}



func (wm *wifiMapper) execute() {
	wm.startBeaconProcessor()
	wm.sniff2GChannels()
	wm.sniff5GChannels()
	wm.stopBeaconProcessor()
	wm.getData()
	wm.displayResults()
}



func (wm *wifiMapper) startBeaconProcessor() {
	wm.sniffer  = sniffer.NewSniffer(wm.iface, getBPFFilter(), false)
	sniffCh    := wm.sniffer.Start()
	wm.dataCh   = make(chan map[wifiData]struct{})

	fmt.Printf("[+] Sniffing beacons\n")

	wm.wg.Add(1)
	go func() {
		defer wm.wg.Done()
		defer close(wm.dataCh)
		wm.processBeacons(sniffCh)
	}()
}



func getBPFFilter() string {
	return "wlan type mgt subtype beacon"
}



func (wm *wifiMapper) processBeacons(sniffCh <-chan []byte) {
	tempBuf   := make(map[wifiData]struct{})
	dissector := dot11dissec.NewDot11Dissector()

	for {
		beacon, ok := <-sniffCh
		if !ok { break }
		dissector.UpdatePkt(beacon)
		wm.updateInfo(dissector, tempBuf)
	}

	wm.dataCh <- tempBuf
}



func (wm *wifiMapper) updateInfo(
	dissector  *dot11dissec.Dot11Dissector,
	tempBuf     map[wifiData]struct{},
) {
	info := wifiData{
		ssid  : dissector.GetSSID(),
		bssid : dissector.GetBSSID(),
		chnl  : dissector.GetChannel(),
		sec   : dissector.GetSecurity(),
		std   : dissector.GetStandard(),
		wps   : dissector.GetWPS(),
		time  : dissector.GetTimestamp(),
	}

	tempBuf[info] = struct{}{}
}



func (wm *wifiMapper) sniff2GChannels() {
	channels := sysconf.Channels2()
	wm.sniffChannels(channels, "2.4")
}



func (wm *wifiMapper) sniff5GChannels() {
	channels := sysconf.Channels5()
	wm.sniffChannels(channels, "5")
}



func (wm *wifiMapper) sniffChannels(channels []int, freq string) {
	var errChannels []int

	for _, chnl := range channels {
		ok := sysconf.TrySetChannel(wm.iface, chnl)

		if ok != nil {
			errChannels = append(errChannels, chnl)
			continue
		}

		time.Sleep(350 * time.Millisecond)
	}

	if len(errChannels) > 0 {
		fmt.Printf("[!] Unable to sniff these channels (%sG):\n%v\n", freq, errChannels)
	}
}



func (wm *wifiMapper) stopBeaconProcessor() {
	wm.sniffer.Stop()
	fmt.Println("[-] Sniffer stopped")
}



func (wm *wifiMapper) getData() {
	wm.wInfo  = <- wm.dataCh
	wm.dataCh = nil
	wm.wg.Wait()
}



func (wm *wifiMapper) displayResults() {
	keys := wm.extractKeysAndMaxLen()
	wm.sortWifiData(keys)
	wm.renderTable(keys)
}



func (wm *wifiMapper) extractKeysAndMaxLen() ([]wifiData) {
	keys := make([]wifiData, 0, len(wm.wInfo))
	
	for netData := range wm.wInfo {
		keys = append(keys, netData)
		wm.getMaxLen(&netData)
	}

	wm.wInfo = nil
    return keys
}



func (wm *wifiMapper) getMaxLen(netData *wifiData) {
	lenSSID := len(netData.ssid)
	if lenSSID > wm.maxLen.ssid { wm.maxLen.ssid = lenSSID }
	
	lenSec := len(netData.sec)
	if lenSec > wm.maxLen.sec { wm.maxLen.sec = lenSec }

	lenWPS := len(netData.wps)
	if lenWPS > wm.maxLen.wps { wm.maxLen.wps = lenWPS }
}



func (wm *wifiMapper) sortWifiData(keys []wifiData) {
	slices.SortFunc(keys, func(a, b wifiData) int {
		if a.ssid != b.ssid {
			if a.ssid < b.ssid {
				return -1
			}
			return 1
		}

		return int(a.chnl) - int(b.chnl)
	})
}



func (wm *wifiMapper) renderTable(keys []wifiData) {
	wm.displayHeader()

	for _, netData := range keys {
		wm.displayWifiInfo(netData)
	}
}



func (wm *wifiMapper) displayHeader() {
	fmt.Printf(
        "\n%-*s  %-17s  %-3s  %-8s  %-*s  %-*s  %s\n",
		wm.maxLen.ssid, "SSID", 
		"BSSID", 
		"Ch", 
		"Std", 
		wm.maxLen.sec, "Sec",
		wm.maxLen.wps, "WPS",
		"UPTIME",
	)

	fmt.Printf(
		"%s  %s  %s  %s  %s  %s  %s\n",
		strings.Repeat("-", wm.maxLen.ssid),
		strings.Repeat("-", 17),
		strings.Repeat("-", 3),
		strings.Repeat("-", 8),
		strings.Repeat("-", wm.maxLen.sec),
		strings.Repeat("-", wm.maxLen.wps),
		strings.Repeat("-", 6),
	)
}



func (wm *wifiMapper) displayWifiInfo(netData wifiData) {
	bssidStr := conv.Byte6ToStr(netData.bssid)

	line := fmt.Sprintf(
		"%-*s  %-17s  %-3d  %-8s  %-*s  %-*s  %s\n",
		wm.maxLen.ssid, netData.ssid, 
		bssidStr, 
		netData.chnl, 
		netData.std, 
		wm.maxLen.sec, netData.sec,
		wm.maxLen.wps, netData.wps, 
		netData.time,
	)

	fmt.Print(line)
}