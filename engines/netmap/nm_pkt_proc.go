package netmap

import (
	"fmt"
	"maps"
	"math/bits"
	"net"
	"offscan/conv"
	"offscan/dissectors"
	"offscan/pktsniff"
)



func (nm *NetworkMapper) startPacketProcessor() {
    nm.sniffer   = pktsniff.NewSniffer(nm.iface, nm.getBPFFilter(), false)
    nm.snifferCh = nm.sniffer.Start()

    go func() {
        tempMap := make(map[[4]byte]Info)
        
		for {
            pkt, ok := <-nm.snifferCh
            if !ok { break }
            nm.dissectAndUpdate(pkt, tempMap)
        }

        nm.mut.Lock()
		maps.Copy(nm.activeIPs, tempMap)
		nm.mut.Unlock()
    }()
}



func (nm *NetworkMapper) getBPFFilter() string {
    return fmt.Sprintf("dst host %s and src net %s", nm.myIP.String(), nm.cidrForBPFFilter())
}



func (nm *NetworkMapper) cidrForBPFFilter() string {
    xor := nm.ips.StartU32 ^ nm.ips.EndU32
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
    
	networkAddr := nm.ips.StartU32 & mask
    ip 			:= conv.U32ToIP(networkAddr)
    
	return fmt.Sprintf("%s/%d", ip.String(), prefixLen)
}



func (nm *NetworkMapper) dissectAndUpdate(pkt []byte, tempMap map[[4]byte]Info) {
    dissector := dissectors.NewPacketDissector()
    dissector.UpdatePkt(pkt)

    srcIP, ok := dissector.GetSrcIP()
    if !ok {
        return
    }
    ipBytes := [4]byte(srcIP.To4())

    if !nm.isInRange(srcIP) {
        return
    }

	if _, exists := tempMap[ipBytes]; exists {
        return
    }

    mac, _ := dissector.GetSrcMac()
    tempMap[ipBytes] = Info{Mac: mac, Name: ""}
}



func (nm *NetworkMapper) isInRange(ip net.IP) bool {
    ipU32 := conv.IPToU32(ip)
    return ipU32 >= nm.ips.StartU32 && ipU32 <= nm.ips.EndU32
}