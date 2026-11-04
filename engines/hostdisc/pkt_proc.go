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
	"context"
	"offscan/internal/models"
	"offscan/internal/pktdissec"
	"offscan/internal/sniffer"
	"time"
)


type hostInfo struct {
    mac  models.MAC
    ip   models.IPv4
}



func (hd *hostDiscovery) startPacketProcessor() {
    hd.dissector = *pktdissec.NewPacketDissector()
    hd.sniffer   = *sniffer.NewSniffer(hd.iface, hd.getBpfFilter(), false, hd.Handler)
    hd.sniffer.Start()
}



func (hd *hostDiscovery) Handler(pkt []byte) {
    hd.lastPkt.Store(time.Now().UnixNano())
    hd.dissector.UpdatePkt(pkt)

    if hd.dissector.IsARP() && hd.dissector.IsArpReply() {
        hd.processArpPkt()
        return
    }

    if hd.dissector.IsIPv4() {
        hd.processIpPkt()
    }
}



func (hd *hostDiscovery) waitForResponses(ctx context.Context, maxWait, idle time.Duration) {
    deadline := time.Now().Add(maxWait)
    for {
        select {
        case <-ctx.Done():
            return
        default:
        }
        if time.Now().After(deadline) {
            return
        }
        last := hd.lastPkt.Load()
        if last > 0 && time.Since(time.Unix(0, last)) > idle {
            return
        }
        time.Sleep(50 * time.Millisecond)
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

    hd.activeIPs.Add(info)
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

    hd.activeIPs.Add(info)
}



func (hd *hostDiscovery) isInRange(ip models.IPv4) bool {
    ipU32 := ip.Uint32()
    return ipU32 >= hd.ips.StartU32 && ipU32 <= hd.ips.EndU32
}



func (hd *hostDiscovery) stopPacketProcessor() {
    hd.sniffer.Stop()
    hd.wgPktProc.Wait()
}