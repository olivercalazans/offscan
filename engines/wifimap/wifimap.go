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

    wifis   := wm.wifis
    wm.wifis = make(map[string]WifiData)

    wm.displayHeader(maxLen)

    ssids := make([]string, 0, len(wifis))
    for ssid := range wifis {
        ssids = append(ssids, ssid)
    }
    sort.Strings(ssids)

    for _, ssid := range ssids {
        info := wifis[ssid]
        wm.displayWifiInfo(ssid, &info, maxLen)
    }
}



func (wm *WifiMapper) displayHeader(maxLen int) {
    fmt.Printf("\n%-*s  %-17s  %s  %s   %s\n",
        maxLen, "SSID", "BSSID", "Channel", "Sec", "Freq")

		fmt.Printf("%s  %s  %s  %s  %s\n",
        strings.Repeat("-", maxLen),
        strings.Repeat("-", 17),
        strings.Repeat("-", 7),
        strings.Repeat("-", 4),
        strings.Repeat("-", 4))
}



func (wm *WifiMapper) displayWifiInfo(ssid string, info *WifiData, maxLen int) {
    // Coleta todas as chaves (BSSIDs) em um slice vazio
    bssidStrs := make([]string, 0, len(info.BSSIDs))
    for bssid := range info.BSSIDs {
        bssidStrs = append(bssidStrs, bssid)
    }
    // Ordena para consistência (opcional, mas recomendado)
    sort.Strings(bssidStrs)

    firstBSSID := "N/A"
    if len(bssidStrs) > 0 {
        firstBSSID = bssidStrs[0]
    }

    line := fmt.Sprintf("%-*s  %-17s  %-7d  %-4s  %sG\n",
        maxLen, ssid, firstBSSID, info.Channel, info.Sec, info.Freq)
    
    fmt.Print(line)

    for i := 1; i < len(bssidStrs); i++ {
        fmt.Printf("%-*s  %-17s\n", maxLen, "", bssidStrs[i])
    }

    sepLine := strings.Repeat("-", len(line))
    fmt.Println(sepLine)
}