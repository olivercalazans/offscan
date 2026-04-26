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
	"sync"
	"time"

	"offscan/internal/conv"
	"offscan/internal/ifconfig"
	"offscan/internal/pktdissector"
	"offscan/internal/pktsniffer"
)



type MonitorSniff struct {
    iface     *net.Interface
    wifisBuf  *map[string]wifiData
    buffer     map[string]wifiData      
    mut        sync.Mutex
    cancel     chan struct{}
    wg         sync.WaitGroup
    sniffer   *pktsniffer.Sniffer
}



func NewMonitorSniff(iface *net.Interface, wifisBuf *map[string]wifiData) *MonitorSniff {
    return &MonitorSniff{
        iface:    iface,
        wifisBuf: wifisBuf,
        buffer:   make(map[string]wifiData),
        cancel:   make(chan struct{}),
    }
}



func (m *MonitorSniff) ExecuteMonitorSniff() {
    m.startBeaconProcessor()
    m.sniff2GChannels()
    m.sniff5GChannels()
    m.stopBeaconProcessor()
    m.sendData()
}



func (m *MonitorSniff) startBeaconProcessor() {
    m.sniffer  = pktsniffer.NewSniffer(m.iface, getBPFFilter(), false)
    packetCh  := m.sniffer.Start()

    m.wg.Add(1)
    go func() {
        defer m.wg.Done()

        tempBuf := make(map[string]wifiData)
        
		for {
			pkt, ok := <-packetCh
            if !ok { break }
            m.dissectAndUpdate(tempBuf, pkt)
        }

        m.mut.Lock()
        maps.Copy(m.buffer, tempBuf)
		m.mut.Unlock()
    }()
}



func getBPFFilter() string {
    return "type mgt and subtype beacon"
}



func (m *MonitorSniff) dissectAndUpdate(tempBuf map[string]wifiData, beacon []byte) {
    info, ok := pktdissector.DissecBeacon(beacon)
    
	if !ok || len(info) < 4 {
        return
    }
    
	ssid     := info[0]
    bssidStr := info[1]
    chnl     := conv.StrToU8(info[2])
    sec      := info[3]
    bssid    := conv.MustStrToMac(bssidStr)
    freq     := getFrequency(chnl)

    m.addInfo(tempBuf, ssid, bssid.String(), chnl, freq, sec)
}



func getFrequency(chnl uint8) string {
    if chnl <= 14 {
        return "2.4"
    }
    return "5"
}



func (m *MonitorSniff) addInfo(
	tempBuf  map[string]wifiData, 
	ssid     string, 
	bssid    string, 
	chnl     uint8, 
	freq     string,
	sec      string,
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
   			BSSIDs:   map[string]struct{}{bssid: {}},
			Channel:  chnl,
            Freq:     freq,
            Sec:      sec,
        }
    }
}



func (m *MonitorSniff) sniff2GChannels() {
    channels := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}
    m.sniffChannels(channels, "2.4")
}



func (m *MonitorSniff) sniff5GChannels() {
    channels := []int{
        36,  40,  44,  48,  52,  56,  60,  64,  100, 104, 108, 112, 116, 120, 
        124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165,
    }
    m.sniffChannels(channels, "5")
}



func (m *MonitorSniff) sniffChannels(channels []int, freq string) {
    var errChannels []int

	for _, chnl := range channels {
        ok := ifconfig.TrySetChannel(m.iface, chnl)

		if ok != nil {
            errChannels = append(errChannels, chnl)
            continue
        }

		time.Sleep(300 * time.Millisecond)
    }

	if len(errChannels) > 0 {
        fmt.Printf("[!] Unable to sniff these channels (%sG):\n%v\n", freq, errChannels)
    }
}



func (m *MonitorSniff) stopBeaconProcessor() {
    m.sniffer.Stop()
    m.wg.Wait()
}



func (m *MonitorSniff) sendData() {
    m.mut.Lock()
    defer m.mut.Unlock()

    *m.wifisBuf = make(map[string]wifiData)

    for k, v := range m.buffer {
        (*m.wifisBuf)[k] = v
    }

    m.buffer = make(map[string]wifiData)
}