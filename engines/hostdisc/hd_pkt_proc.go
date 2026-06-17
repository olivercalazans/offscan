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
	"offscan/internal/pktdissec"
	"offscan/internal/sniffer"
)


type hostInfo struct {
    Mac  net.HardwareAddr
    Name string
}



func (hd *hostDiscovery) startPacketProcessor() {
    hd.sniffer   = sniffer.NewSniffer(hd.iface, hd.getBpfFilter(), false)
    hd.snifferCh = hd.sniffer.Start()

    hd.wgPktProc.Add(1)
    go func() {
        defer hd.wgPktProc.Done()

        tempMap := make(map[[4]byte]hostInfo)
        
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



func (hd *hostDiscovery) getBpfFilter() string {
    return fmt.Sprintf(
        "(dst host %s and src net %s) or (arp[6:2] = 2)", 
        hd.myIP.String(),
        hd.cidrForBPFFilter(),
    )
}



func (hd *hostDiscovery) cidrForBPFFilter() string {
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



func (hd *hostDiscovery) dissectAndUpdate(pkt []byte, tempMap map[[4]byte]hostInfo) {
    dissector := pktdissec.NewPacketDissector()
    dissector.UpdatePkt(pkt)

    if dissector.IsARP() && dissector.IsArpReply() {
        hd.processArpPkt(dissector, tempMap)
        return
    }

    if dissector.IsIPv4() {
        hd.processIpPkt(dissector, tempMap)
    }
}



func (hd *hostDiscovery) processArpPkt(dissector *pktdissec.PacketDissector, tempMap map[[4]byte]hostInfo) {
    var ok bool

    srcIP, ok := dissector.GetArpSrcIP()
    if !ok { return }

    ipBytes := [4]byte(srcIP)
    if !hd.isInRange(srcIP) { return }

    srcMAC, ok := dissector.GetArpSrcMAC()
    if !ok { return }

    tempMap[ipBytes] = hostInfo{Mac: srcMAC, Name: ""}
}



func (hd *hostDiscovery) processIpPkt(dissector *pktdissec.PacketDissector, tempMap map[[4]byte]hostInfo) {
    var ok bool

    srcIP, ok := dissector.GetSrcIP()
    if !ok { return }

    ipBytes := [4]byte(srcIP)
    if !hd.isInRange(srcIP) { return }

    srcMAC, ok := dissector.GetEtherSrcMAC()
    if !ok { return }

    tempMap[ipBytes] = hostInfo{Mac: srcMAC, Name: ""}
}



func (hd *hostDiscovery) isInRange(ip net.IP) bool {
    ipU32 := conv.IPToU32(ip)
    return ipU32 >= hd.ips.StartU32 && ipU32 <= hd.ips.EndU32
}



func (hd *hostDiscovery) stopPacketProcessor() {
    if hd.sniffer != nil {
        hd.sniffer.Stop()
    }
    
    hd.wgPktProc.Wait()
}