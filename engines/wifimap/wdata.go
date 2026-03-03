package wifimap

import (
	"net"
)



type WifiData struct {
    BSSIDs   map[string]struct{}
    Channel  uint8
    Freq     string
    Sec      string
}



func NewWifiData(bssid net.HardwareAddr, channel uint8, freq, sec string) *WifiData {
    bssids := make(map[string]struct{})
    bssids[bssid.String()] = struct{}{}
    
	return &WifiData{
        BSSIDs:  bssids,
        Channel: channel,
        Freq:    freq,
        Sec:     sec,
    }
}