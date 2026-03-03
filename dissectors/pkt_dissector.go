package dissectors

import (
	"encoding/binary"
	"net"
)



type PacketDissector struct {
    pkt []byte
}



func NewPacketDissector() *PacketDissector {
    return &PacketDissector{
        pkt: make([]byte, 0),
    }
}



func (pd *PacketDissector) UpdatePkt(raw []byte) {
    pd.pkt = raw
}



func (pd *PacketDissector) isIPv4() bool {
    if len(pd.pkt) < 14 {
        return false
    }

	ethertype := binary.BigEndian.Uint16(pd.pkt[12:14])
    return ethertype == 0x0800
}



func (pd *PacketDissector) ihl() (uint8, bool) {
    if len(pd.pkt) < 15 {
        return 0, false
    }

	ihl := pd.pkt[14] & 0x0F

	if ihl < 5 {
        return 0, false
    }

	return ihl, true
}



func (pd *PacketDissector) ipHeaderLen() (int, bool) {
    ihl, ok := pd.ihl()
    
	if !ok {
        return 0, false
    }
    
	return 14 + int(ihl)*4, true
}



func (pd *PacketDissector) isTCP() bool {
    if len(pd.pkt) < 24 {
        return false
    }
    
	return pd.pkt[23] == 6
}



func (pd *PacketDissector) isUDP() bool {
	if len(pd.pkt) < 24 {
        return false
    }

	return pd.pkt[23] == 17
}



func (pd *PacketDissector) GetSrcMac() (net.HardwareAddr, bool) {
    if len(pd.pkt) < 12 {
        return nil, false
    }
    
	mac := make([]byte, 6)
    copy(mac, pd.pkt[6:12])
    
	return net.HardwareAddr(mac), true
}



func (pd *PacketDissector) GetSrcIP() (net.IP, bool) {
    if len(pd.pkt) < 30 || !pd.isIPv4() {
        return nil, false
    }
    
	ip := net.IP(pd.pkt[26:30]).To4()
    
	if ip == nil {
        return nil, false
    }
    
	return ip, true
}



func (pd *PacketDissector) GetTCPSrcPort() (uint16, bool) {
    if len(pd.pkt) < 54 || !pd.isIPv4() || !pd.isTCP() {
        return 0, false
    }

	offset, ok := pd.ipHeaderLen()
    if !ok {
        return 0, false
    }

	if len(pd.pkt) < offset+2 {
        return 0, false
    }

	port := binary.BigEndian.Uint16(pd.pkt[offset : offset+2])
    return port, true
}



func (pd *PacketDissector) GetUDPSrcPort() (uint16, bool) {
    if len(pd.pkt) < 42 || !pd.isIPv4() || !pd.isUDP() {
        return 0, false
    }

	offset, ok := pd.ipHeaderLen()
    if !ok {
        return 0, false
    }

	if len(pd.pkt) < offset+2 {
        return 0, false
    }

	port := binary.BigEndian.Uint16(pd.pkt[offset : offset+2])
    return port, true
}