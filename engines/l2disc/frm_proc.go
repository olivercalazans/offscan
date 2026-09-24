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
	"offscan/internal/dot11dissec"
	"offscan/internal/models"
)



type frameProcessor struct {
	dissector  *dot11dissec.Dot11Dissector
	idx         uint
	missBuf     map[station]struct{}
	netsBuf     map[models.MAC]beacon
	stasBuf     map[station]struct{}
}



func (fp *frameProcessor) init() {
	fp.dissector = dot11dissec.NewDot11Dissector()
	fp.netsBuf   = make(map[models.MAC]beacon)
	fp.stasBuf   = make(map[station]struct{})
	fp.missBuf   = make(map[station]struct{})
}



func (fp *frameProcessor) Handler(frame []byte) {
	fp.dissector.UpdatePkt(frame)

	if fp.dissector.IsBeacon {
		bssid := fp.dissector.GetBSSID()
		netInfo := beacon{
			ssid: fp.dissector.GetSSID(),
			chnl: fp.dissector.GetChannel(),
		}
		
		fp.netsBuf[bssid] = netInfo
		fp.associateStas(bssid)
		return
	}

	if fp.dissector.IsDataFrm {
		bssid, staMac, ok := fp.dissector.GetAddrs()
		if !ok { return }
		
		staInfo := station{ bssid: bssid, staMac: staMac }
		fp.addStation(staInfo)
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
    netInfo, ok := fp.netsBuf[staInfo.bssid]

    if !ok {
        fp.missBuf[staInfo] = struct{}{}
        return
    }

    if _, exists := fp.stasBuf[staInfo]; exists {
        return
    }
    
	fp.stasBuf[staInfo] = struct{}{}
    fp.displayStation(&netInfo, &staInfo)
}



func (fp *frameProcessor) displayStation(netInfo *beacon, sta *station) {
	fp.idx++

	fmt.Printf(
		"%d. %s  %s  %-3d  %s\n",
		fp.idx,
		sta.staMac.String(),
		sta.bssid.String(), 
		netInfo.chnl,
		netInfo.ssid.String(),
	)
}