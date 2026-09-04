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

package hostdisc

import (
	"offscan/internal/models"
	"offscan/internal/pktdissec"
)


type hostInfo struct {
    ip   models.IPv4
    mac  models.MAC
}



func (hd *hostDiscovery) startPacketProcessor() {
    hd.dissector = *pktdissec.NewPacketDissector()

    hd.wgPktProc.Add(1)
    go func() {
        defer hd.wgPktProc.Done()
        
		for {
            pkt, ok := <-hd.snifferCh
            if !ok { break }
            hd.dissector.UpdatePkt(pkt)
            hd.processPkt()
        }
    }()
}



func (hd *hostDiscovery) processPkt() {
    if hd.dissector.IsARP() && hd.dissector.IsArpReply() {
        hd.processArpPkt()
        return
    }

    if hd.dissector.IsIPv4() {
        hd.processIpPkt()
    }
}



func (hd *hostDiscovery) processArpPkt() {
    var ok bool

    srcIP, ok := hd.dissector.GetArpSrcIP()
    if !ok { return }

    if !hd.isInRange(srcIP) { return }

    srcMAC, ok := hd.dissector.GetArpSrcMAC()
    if !ok { return }

    info := hostInfo{
        ip  : srcIP,
        mac : srcMAC,
    }

    hd.activeIPs[info] = ""
}



func (hd *hostDiscovery) processIpPkt() {
    var ok bool

    srcIP, ok := hd.dissector.GetSrcIP()
    if !ok { return }

    if !hd.isInRange(srcIP) { return }

    srcMAC, ok := hd.dissector.GetEtherSrcMAC()
    if !ok { return }

    info := hostInfo{
        ip  : srcIP,
        mac : srcMAC,
    }

    hd.activeIPs[info] = ""
}



func (hd *hostDiscovery) isInRange(ip models.IPv4) bool {
    ipU32 := ip.Uint32()
    return ipU32 >= hd.ips.StartU32 && ipU32 <= hd.ips.EndU32
}



func (hd *hostDiscovery) stopPacketProcessor() {
    hd.sniffer.Stop()
    hd.wgPktProc.Wait()
}