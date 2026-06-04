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
	"maps"
	"net"
	"offscan/internal/conv"
	"offscan/internal/frame80211/dissector"
	"offscan/internal/ifconfig"
	"offscan/internal/sniffer"
	"slices"
	"strings"
	"sync"
	"time"
)


func Run(args []string) {
	newWifiMapper(args).execute()
}



type wifiData struct {
	ssid  string
	bssid [6]byte
	chnl  uint8
	sec   string
	std   string
}



type wifiMapper struct {
	iface     net.Interface

	wInfo     map[wifiData]struct{}
	sniffer  *sniffer.Sniffer
	mut       sync.Mutex
	wg        sync.WaitGroup
	cancel    chan struct{}
}



func newWifiMapper(argList []string) *wifiMapper {
	parser := newParser()
	parser.parseWMapArgs(argList)

	return &wifiMapper{
		wInfo: make(map[wifiData]struct{}),
		iface: conv.MustStrToIface(parser.Iface),
	}
}



func (wm *wifiMapper) execute() {
	wm.startBeaconProcessor()
	wm.sniff2GChannels()
	wm.sniff5GChannels()
	wm.stopBeaconProcessor()
	wm.displayResults()
}



func (wm *wifiMapper) startBeaconProcessor() {
	wm.sniffer  = sniffer.NewSniffer(wm.iface, getBPFFilter(), false)
	sniffCh    := wm.sniffer.Start()

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
	tempBuf   := make(map[wifiData]struct{})
	dissector := dissector.NewDot11Dissector()

	for {
		beacon, ok := <-sniffCh
		if !ok { break }
		dissector.UpdatePkt(beacon)
		wm.updateInfo(dissector, tempBuf)
	}

	wm.mut.Lock()
	maps.Copy(wm.wInfo, tempBuf)
	wm.mut.Unlock()
}



func (wm *wifiMapper) updateInfo(
	dissector  *dissector.Dot11Dissector,
	tempBuf     map[wifiData]struct{},
) {
	info := wifiData{
		ssid  : dissector.GetSSID(),
		bssid : dissector.GetBSSID(),
		chnl  : dissector.GetChannel(),
		sec   : dissector.GetSecurity(),
		std   : dissector.GetStandard(),
	}

	tempBuf[info] = struct{}{}
}



func (wm *wifiMapper) sniff2GChannels() {
	channels := ifconfig.Channels2()
	wm.sniffChannels(channels, "2.4")
}



func (wm *wifiMapper) sniff5GChannels() {
	channels := ifconfig.Channels5()
	wm.sniffChannels(channels, "5")
}



func (wm *wifiMapper) sniffChannels(channels []int, freq string) {
	var errChannels []int

	for _, chnl := range channels {
		ok := ifconfig.TrySetChannel(wm.iface, chnl)

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
	keys, maxLen := wm.extractKeysAndMaxLen()
	wm.sortWifiData(keys)
	wm.renderTable(keys, maxLen)
}



func (wm *wifiMapper) extractKeysAndMaxLen() ([]wifiData, int) {
	maxLen := 4
	keys   := make([]wifiData, 0, len(wm.wInfo))
	
	for netData := range wm.wInfo {
		keys = append(keys, netData)

        if len(netData.ssid) > maxLen {
			maxLen = len(netData.ssid)
		}
	}

    return keys, maxLen
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



func (wm *wifiMapper) renderTable(keys []wifiData, maxLen int) {
	wm.displayHeader(maxLen)

	for _, netData := range keys {
		wm.displayWifiInfo(netData, maxLen)
	}
}



func (wm *wifiMapper) displayHeader(maxLen int) {
	fmt.Printf(
        "\n%-*s  %-17s  %-3s  %-8s  %s\n",
		maxLen, "SSID", "BSSID", "Ch", "Std", "Sec",
	)

	fmt.Printf(
		"%s  %s  %s  %s  %s\n",
		strings.Repeat("-", maxLen),
		strings.Repeat("-", 17),
		strings.Repeat("-", 3),
		strings.Repeat("-", 8),
		strings.Repeat("-", 6),
	)
}



func (wm *wifiMapper) displayWifiInfo(netData wifiData, maxLen int) {
	bssidStr := conv.Byte6ToStr(netData.bssid)

	line := fmt.Sprintf(
		"%-*s  %-17s  %-3d  %-8s  %-s\n",
		maxLen, netData.ssid, bssidStr, netData.chnl, netData.std, netData.sec,
	)

	fmt.Print(line)
}