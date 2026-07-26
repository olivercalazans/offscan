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


func (l2hd *layer2HostDiscovery) processFrame(sniffCh <-chan []byte) {
	dissector := dot11dissec.NewDot11Dissector()

	for {
		frame, ok := <-sniffCh
		if !ok { break }
		dissector.UpdatePkt(frame)
		l2hd.sendToUpdate(dissector)
	}
}



func (l2hd *layer2HostDiscovery) sendToUpdate(dissector *dot11dissec.Dot11Dissector) {
	info := dot11Info{}

	if dissector.IsBeacon {
		info.isBeacon = true
		info.bssid    = dissector.GetBSSID()
		info.chnl     = dissector.GetChannel()
		info.ssid     = dissector.GetSSID()
		
		select {
        case l2hd.eventCh <- info:
        default:
        }
        return
	}

	if dissector.IsDataFrm {
		bssid, staMac, ok := dissector.GetAddrs()
		if !ok { return }
		
		info.isDataFrm = true
		info.bssid     = bssid
		info.staMac    = staMac

		select {
        case l2hd.eventCh <- info:
        default:
        }
	}
}



func (l2hd *layer2HostDiscovery) displayLoop() {
	bufs := buffers{
		nets : make(map[[6]byte]beacon),
		stas : make(map[station]struct{}),
		miss : make(map[station]struct{}),
	}

	for data := range l2hd.eventCh {
		if data.isBeacon {
			netInfo := beacon{ ssid: data.ssid, chnl: data.chnl }
			bufs.nets[data.bssid] = netInfo
			associateStas(&bufs, data.bssid)
		}

		if data.isDataFrm {
			staInfo := station{ bssid: data.bssid, staMac: data.staMac }
			addStation(&bufs, staInfo)
		}
	}
}



func associateStas(bufs *buffers, bssid [6]byte) {
	for sta := range bufs.miss {
        if sta.bssid == bssid {
        	delete(bufs.miss, sta)
            addStation(bufs, sta)
        }
    }
}



func addStation(bufs *buffers, staInfo station) {
    net, ok := bufs.nets[staInfo.bssid]

    if !ok {
        bufs.miss[staInfo] = struct{}{}
        return
    }

    if _, exists := bufs.stas[staInfo]; exists {
        return
    }
    
	bufs.stas[staInfo] = struct{}{}
    displayStation(&net, &staInfo)
}



func displayHeader() {
	fmt.Printf(
        "\n%-17s  %-17s  %-3s  %s\n",
		"STA MAC", "BSSID", "Ch", "SSID",
	)

	fmt.Printf(
		"%s  %s  %s  %s\n",
		strings.Repeat("-", 17),
		strings.Repeat("-", 17),
		strings.Repeat("-", 3),
		strings.Repeat("-", 4),
	)
}



func displayStation(net *beacon, sta *station) {
	fmt.Printf(
		"%s  %s  %-3d  %s\n",
		conv.Byte6ToStr(sta.staMac),
		conv.Byte6ToStr(sta.bssid), 
		net.chnl,
		net.ssid,
	)
}