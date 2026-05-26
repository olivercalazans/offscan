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
	"offscan/internal/utils"
	"strings"
	"sync"
	"time"
)



func Run(args []string) {
    newWifiMapper(args).execute()
}


type wifiData struct {
    BSSIDs   map[string]struct{}
    Channel  uint8
    Freq     string
    Sec      string
    Std      string
}


type wifiMapper struct {
    wInfo     map[string]wifiData
    iface    *net.Interface
    sniffer  *sniffer.Sniffer
    mut       sync.Mutex
    cancel    chan struct{}
    wg        sync.WaitGroup
}



func newWifiMapper(argList []string) *wifiMapper {
	args := ParseWmapArgs(argList)

    return &wifiMapper{
        wInfo: make(map[string]wifiData),
        iface: conv.MustStrToIface(args.Iface),
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
    packetCh   := wm.sniffer.Start()

    fmt.Printf("[+] Sniffing beacons\n")

    wm.wg.Add(1)
    go func() {
        defer wm.wg.Done()
        wm.processPkts(packetCh)
    }()
}



func getBPFFilter() string {
    return "wlan type mgt subtype beacon"
}



func (wm *wifiMapper) processPkts(packetCh <-chan []byte) {
    tempBuf   := make(map[string]wifiData)
    dissector := dissector.NewBeaconDissector()
        
	for {
		beacon, ok := <-packetCh
        if !ok { break }
        dissector.UpdatePkt(beacon)
        wm.dissectAndUpdate(dissector, tempBuf)
    }

    wm.mut.Lock()
    maps.Copy(wm.wInfo, tempBuf)
	wm.mut.Unlock()
}



func (wm *wifiMapper) dissectAndUpdate(
    dissector  *dissector.BeaconDissector,
    tempBuf     map[string]wifiData,
) {
    info, ok := dissector.Dissec()
    
	if !ok || len(info) < 5 {
        return
    }
    
	ssid     := info[0]
    bssidStr := info[1]
    chnl     := conv.StrToU8(info[2])
    sec      := info[3]
    bssid    := conv.MustStrToMac(bssidStr)
    freq     := getFrequency(chnl)
    std      := info[4]

    wm.addInfo(tempBuf, ssid, bssid.String(), chnl, freq, sec, std)
}



func getFrequency(chnl uint8) string {
    if chnl <= 14 {
        return "2.4"
    }
    return "5"
}



func (wm *wifiMapper) addInfo(
	tempBuf  map[string]wifiData, 
	ssid     string, 
	bssid    string, 
	chnl     uint8, 
	freq     string,
	sec      string,
    std      string,
) {
    existing, ok := tempBuf[ssid]

    if ok {
        if _, ok := existing.BSSIDs[bssid]; ok {
            return
        }

        existing.BSSIDs[bssid] = struct{}{} 
        tempBuf[ssid]          = existing

    } else {
        tempBuf[ssid] = wifiData{
   			BSSIDs  : map[string]struct{}{bssid: {}},
			Channel : chnl,
            Freq    : freq,
            Sec     : sec,
            Std     : std,
        }
    }
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
    fmt.Printf("[-] Sniffer stopped\n")
    wm.wg.Wait()
}



func (wm *wifiMapper) displayResults() {
    maxLen := 4
    
	for ssid := range wm.wInfo {
        if len(ssid) > maxLen {
            maxLen = len(ssid)
        }
    }

    wm.displayHeader(maxLen)

    for _, ssid := range utils.SortKeys(wm.wInfo) {
        wm.displayWifiInfo(ssid, maxLen)
    }
}



func (wm *wifiMapper) displayHeader(maxLen int) {
    fmt.Printf("\n%-*s  %-4s  %-17s  %-3s  %-8s  %s\n",
        maxLen, "SSID", "Freq", "BSSID", "Ch", "Std", "Sec",
    )

	fmt.Printf(
        "%s  %s  %s  %s  %s  %s\n",
        strings.Repeat("-", maxLen),
        strings.Repeat("-", 4),
        strings.Repeat("-", 17),
        strings.Repeat("-", 3),
        strings.Repeat("-", 8),
        strings.Repeat("-", 6),
    )
}



func (wm *wifiMapper) displayWifiInfo(ssid string, maxLen int) {
    info := wm.wInfo[ssid]

    bssidStrs := utils.SortKeys(info.BSSIDs)

    firstBSSID := "N/A"
    if len(bssidStrs) > 0 {
        firstBSSID = bssidStrs[0]
    }

    line := fmt.Sprintf(
        "%-*s  %-4s  %-17s  %-3d  %-8s  %-4s\n",
        maxLen, ssid, info.Freq, firstBSSID, info.Channel, info.Std, info.Sec,
    )
    
    fmt.Print(line)

    for i := 1; i < len(bssidStrs); i++ {
        fmt.Printf("%-*s  %-17s\n", maxLen + 6, "", bssidStrs[i])
    }

    sepLine := strings.Repeat("-", len(line))
    fmt.Println(sepLine)
}