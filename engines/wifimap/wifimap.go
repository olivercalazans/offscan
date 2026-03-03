package wifimap

import (
	"fmt"
	"net"
	"offscan/conv"
	"sort"
	"strings"
)



func Run(args []string) {
    New(args).Execute()
}



type WifiMapper struct {
    wifis   map[string]WifiData
    iface  *net.Interface
}



func New(argList []string) *WifiMapper {
	args := ParseWmapArgs(argList)

    return &WifiMapper{
        wifis: make(map[string]WifiData),
        iface: conv.MustGetIface(args.Iface),
    }
}



func (wm *WifiMapper) Execute() {
    wm.executeMode()
    wm.displayResults()
}



func (wm *WifiMapper) executeMode() {
    monSniff := NewMonitorSniff(wm.iface, &wm.wifis)
    monSniff.ExecuteMonitorSniff()
}



func (wm *WifiMapper) displayResults() {
    maxLen := 4
    
	for ssid := range wm.wifis {
        if len(ssid) > maxLen {
            maxLen = len(ssid)
        }
    }

    wifis := wm.wifis
    wm.wifis = make(map[string]WifiData)

    channels := make(map[uint8]bool)
    wm.displayHeader(maxLen)

    ssids := make([]string, 0, len(wifis))
    for ssid := range wifis {
        ssids = append(ssids, ssid)
    }
    sort.Strings(ssids)

    for _, ssid := range ssids {
        info := wifis[ssid]
        wm.displayWifiInfo(ssid, &info, maxLen)
        channels[info.Channel] = true
    }

    chList := make([]int, 0, len(channels))
    for ch := range channels {
        chList = append(chList, int(ch))
    }

	sort.Ints(chList)
    fmt.Printf("\n# Channels found: %v\n", chList)
}



func (wm *WifiMapper) displayHeader(maxLen int) {
    fmt.Printf("\n%-*s  %-17s  %s  %s  %s\n",
        maxLen, "SSID", "BSSID", "Channel", "Sec", "Freq")

		fmt.Printf("%s  %s  %s  %s  %s\n",
        strings.Repeat("-", maxLen),
        strings.Repeat("-", 17),
        strings.Repeat("-", 7),
        strings.Repeat("-", 4),
        strings.Repeat("-", 4))
}



func (wm *WifiMapper) displayWifiInfo(ssid string, info *WifiData, maxLen int) {
	bssidStrs := make([]string, len(info.BSSIDs))

	for bssid := range info.BSSIDs {
        tmpSlice  := append(bssidStrs, bssid)
		bssidStrs  = tmpSlice
    }

    firstBSSID := "N/A"

	if len(bssidStrs) > 0 {
        firstBSSID = bssidStrs[0]
    }

	fmt.Printf("%-*s  %-17s  %-7d  %-4s  %sG\n",
        maxLen, ssid, firstBSSID, info.Channel, info.Sec, info.Freq)

    for i := 1; i < len(bssidStrs); i++ {
        fmt.Printf("%-*s  %-17s\n", maxLen, "", bssidStrs[i])
    }
}