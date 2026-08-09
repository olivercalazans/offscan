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
	"offscan/internal/conv"
	"offscan/internal/dot11dissec"
	"strings"
)



type frameProcessor struct {
	dissector  *dot11dissec.Dot11Dissector
	idx         uint
	eventCh     chan dot11Info
	missBuf     map[station]struct{}
	netsBuf     map[[6]byte]beacon
	stasBuf     map[station]struct{}
}



func (fp *frameProcessor) init() {
	fp.dissector = dot11dissec.NewDot11Dissector()
	fp.netsBuf   = make(map[[6]byte]beacon)
	fp.stasBuf   = make(map[station]struct{})
	fp.missBuf   = make(map[station]struct{})
	fp.eventCh   = make(chan dot11Info, 1024)
}



func (fp *frameProcessor) processFrame(sniffCh <-chan []byte) {
	for {
		frame, ok := <-sniffCh
		if !ok { break }

		fp.dissector.UpdatePkt(frame)
		fp.sendToUpdate()
	}

	close(fp.eventCh)
}



func (fp *frameProcessor) sendToUpdate() {
	info := dot11Info{}

	if fp.dissector.IsBeacon {
		info.isBeacon = true
		info.bssid    = fp.dissector.GetBSSID()
		info.chnl     = fp.dissector.GetChannel()
		info.ssid     = fp.dissector.GetSSID()
		
		select {
        case fp.eventCh <- info:
        default:
        }
        return
	}

	if fp.dissector.IsDataFrm {
		bssid, staMac, ok := fp.dissector.GetAddrs()
		if !ok { return }
		
		info.isDataFrm = true
		info.bssid     = bssid
		info.staMac    = staMac

		select {
        case fp.eventCh <- info:
        default:
        }
	}
}



func (fp *frameProcessor) displayLoop() {
	for data := range fp.eventCh {
		if data.isBeacon {
			netInfo := beacon{ ssid: data.ssid, chnl: data.chnl }
			fp.netsBuf[data.bssid] = netInfo
			fp.associateStas(data.bssid)
		}

		if data.isDataFrm {
			staInfo := station{ bssid: data.bssid, staMac: data.staMac }
			fp.addStation(staInfo)
		}
	}
}



func (fp *frameProcessor) associateStas(bssid [6]byte) {
	for sta := range fp.missBuf {
        if sta.bssid == bssid {
        	delete(fp.missBuf, sta)
            fp.addStation(sta)
        }
    }
}



func (fp *frameProcessor) addStation(staInfo station) {
    net, ok := fp.netsBuf[staInfo.bssid]

    if !ok {
        fp.missBuf[staInfo] = struct{}{}
        return
    }

    if _, exists := fp.stasBuf[staInfo]; exists {
        return
    }
    
	fp.stasBuf[staInfo] = struct{}{}
    fp.displayStation(&net, &staInfo)
}



func displayHeader() {
	fmt.Printf(
        "\n   %-17s  %-17s  %-3s  %s\n",
		"STA MAC", "BSSID", "Ch", "SSID",
	)

	fmt.Printf(
		"   %s  %s  %s  %s\n",
		strings.Repeat("-", 17),
		strings.Repeat("-", 17),
		strings.Repeat("-", 3),
		strings.Repeat("-", 4),
	)
}



func (fp *frameProcessor) displayStation(net *beacon, sta *station) {
	fp.idx++

	fmt.Printf(
		"%d. %s  %s  %-3d  %s\n",
		fp.idx,
		conv.Byte6ToStr(sta.staMac),
		conv.Byte6ToStr(sta.bssid), 
		net.chnl,
		net.ssid,
	)
}