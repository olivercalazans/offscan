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
	iface       net.Interface
	wInfo       map[wifiData]struct{}
	sniffer    *sniffer.Sniffer
	dataCh      chan map[wifiData]struct{}
	wg          sync.WaitGroup
	cancel      chan struct{}
	maxLen      maxLength
	dissector  *dot11dissec.Dot11Dissector
}



func (wm *wifiMapper) execute() {
	wm.startBeaconProcessor()
	wm.sniff2GChannels()
	wm.sniff5GChannels()
	wm.stopBeaconProcessor()
	wm.displayResults()
}



func (wm *wifiMapper) startBeaconProcessor() {
	wm.sniffer    = sniffer.NewSniffer(wm.iface, getBPFFilter(), false)
	sniffCh      := wm.sniffer.Start()
	wm.dissector  = dot11dissec.NewDot11Dissector()

	fmt.Printf("[+] Sniffing beacons\n")

	wm.wg.Add(1)
	go func() {
		defer wm.wg.Done()
		wm.processBeacons(sniffCh)
	}()
}



func getBPFFilter() string {
	return "wlan type mgt subtype beacon"
}



func (wm *wifiMapper) processBeacons(sniffCh <-chan []byte) {
	for {
		beacon, ok := <-sniffCh
		if !ok { break }
		wm.dissector.UpdatePkt(beacon)
		wm.updateInfo()
	}
}



func (wm *wifiMapper) updateInfo() {
	info := wifiData{
		ssid  : wm.dissector.GetSSID(),
		bssid : wm.dissector.GetBSSID(),
		chnl  : wm.dissector.GetChannel(),
		sec   : wm.dissector.GetSecurity(),
		std   : wm.dissector.GetStandard(),
		wps   : wm.dissector.GetWPS(),
		time  : wm.dissector.GetTimestamp(),
	}

	wm.wInfo[info] = struct{}{}
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
	wm.wg.Wait()
}



func (wm *wifiMapper) displayResults() {
	keys := wm.extractKeysAndMaxLen()
	wm.sortWifiData(keys)
	wm.renderTable(keys)
}



func (wm *wifiMapper) extractKeysAndMaxLen() []wifiData {
	keys := make([]wifiData, 0, len(wm.wInfo))
	
	for netData := range wm.wInfo {
		keys = append(keys, netData)
		wm.getMaxLen(&netData)
	}

	wm.wInfo = nil
    return keys
}



func (wm *wifiMapper) getMaxLen(netData *wifiData) {
	if netData.ssid.Len() > wm.maxLen.ssid { wm.maxLen.ssid = netData.ssid.Len() }
	
	lenSec := len(netData.sec)
	if lenSec > wm.maxLen.sec { wm.maxLen.sec = lenSec }

	lenWPS := netData.wps.Len()
	if lenWPS > wm.maxLen.wps { wm.maxLen.wps = lenWPS }
}



func (wm *wifiMapper) sortWifiData(keys []wifiData) {
    slices.SortFunc(keys, func(a, b wifiData) int {
        if a.ssid.IsHidden != b.ssid.IsHidden {
            if a.ssid.IsHidden {
                return -1
            }
            return 1
        }

        if a.ssid.IsUnknown != b.ssid.IsUnknown {
            if a.ssid.IsUnknown {
                return -1
            }
            return 1
        }

        aLen := a.ssid.Len()
        bLen := b.ssid.Len()

        minLen := aLen
        if bLen < minLen {
            minLen = bLen
        }

        for i := 0; i < minLen; i++ {
            if a.ssid.Data[i] < b.ssid.Data[i] {
                return -1
            }
            if a.ssid.Data[i] > b.ssid.Data[i] {
                return 1
            }
        }

        if aLen != bLen {
            return aLen - bLen
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
	line := fmt.Sprintf(
		"%-*s  %-17s  %-3d  %-8s  %-*s  %-*s  %s\n",
		wm.maxLen.ssid, netData.ssid.String(), 
		netData.bssid.String(), 
		netData.chnl, 
		netData.std.String(),
		wm.maxLen.sec, netData.sec,
		wm.maxLen.wps, netData.wps.String(), 
		netData.time.String(),
	)

	fmt.Print(line)
}