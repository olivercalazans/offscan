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
	"fmt"
	"maps"
	"math/bits"
	"net"
	"offscan/internal/conv"
	"offscan/internal/pktdissector"
	"offscan/internal/pktsniffer"
)



func (hd *HostDiscovery) startPacketProcessor() {
    hd.sniffer   = pktsniffer.NewSniffer(hd.iface, hd.getBPFFilter(), false)
    hd.snifferCh = hd.sniffer.Start()

    hd.wgPktProc.Add(1)
    go func() {
        defer hd.wgPktProc.Done()

        tempMap := make(map[[4]byte]Info)
        
		for {
            pkt, ok := <-hd.snifferCh
            if !ok { break }
            hd.dissectAndUpdate(pkt, tempMap)
        }

        hd.mut.Lock()
		maps.Copy(hd.activeIPs, tempMap)
		hd.mut.Unlock()
    }()
}



func (hd *HostDiscovery) getBPFFilter() string {
    return fmt.Sprintf("dst host %s and src net %s", hd.myIP.String(), hd.cidrForBPFFilter())
}



func (hd *HostDiscovery) cidrForBPFFilter() string {
    xor := hd.ips.StartU32 ^ hd.ips.EndU32
    var leadingZeros int
    
	if xor == 0 {
        leadingZeros = 32
    } else {
        leadingZeros = bits.LeadingZeros32(xor)
	}
    
	prefixLen := uint8(leadingZeros)
    var mask uint32
    
	if prefixLen == 0 {
        mask = 0
    } else {
        mask = ^uint32(0) << (32 - prefixLen)
    }
    
	networkAddr := hd.ips.StartU32 & mask
    ip 			:= conv.U32ToIP(networkAddr)
    
	return fmt.Sprintf("%s/%d", ip.String(), prefixLen)
}



func (hd *HostDiscovery) dissectAndUpdate(pkt []byte, tempMap map[[4]byte]Info) {
    dissector := pktdissector.NewPacketDissector()
    dissector.UpdatePkt(pkt)

    srcIP, ok := dissector.GetSrcIP()
    if !ok {
        return
    }
    ipBytes := [4]byte(srcIP.To4())

    if !hd.isInRange(srcIP) {
        return
    }

	if _, exists := tempMap[ipBytes]; exists {
        return
    }

    mac, _ := dissector.GetSrcMac()
    tempMap[ipBytes] = Info{Mac: mac, Name: ""}
}



func (hd *HostDiscovery) isInRange(ip net.IP) bool {
    ipU32 := conv.IPToU32(ip)
    return ipU32 >= hd.ips.StartU32 && ipU32 <= hd.ips.EndU32
}



func (hd *HostDiscovery) stopPacketProcessor() {
    hd.sniffer.Stop()
    hd.wgPktProc.Wait()
}