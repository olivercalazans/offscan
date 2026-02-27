package packet

import (
	"encoding/binary"
	"net"
)


type IcmpPkt struct {
	buffer [42]byte
}



func NewIcmpPkt() *IcmpPkt {
	p := &IcmpPkt{}
	p.buildFixed()
	return p
}



func (p *IcmpPkt) buildFixed() {
	// Ethernet header (0-13)
	binary.BigEndian.PutUint16(p.buffer[12:14], 0x0800)
	
	// IP header (14-33)
	p.buffer[14] = (4 << 4) | 5
	p.buffer[15] = 0
	binary.BigEndian.PutUint16(p.buffer[16:18], 28)
	binary.BigEndian.PutUint16(p.buffer[18:20], 0x1234)
	binary.BigEndian.PutUint16(p.buffer[20:22], 0x4000)
	p.buffer[22] = 64
	p.buffer[23] = 1
	binary.BigEndian.PutUint16(p.buffer[24:26], 0)

	// ICMP header (34-41)
	p.buffer[34] = 8
	p.buffer[35] = 0
	binary.BigEndian.PutUint16(p.buffer[36:38], 0)
	binary.BigEndian.PutUint16(p.buffer[38:40], 0x1234)
	binary.BigEndian.PutUint16(p.buffer[40:42], 1)

	ck := IcmpSum(p.buffer[34:42])
	binary.BigEndian.PutUint16(p.buffer[36:38], ck)
}



func (p *IcmpPkt) etherHeader(srcMAC, dstMAC net.HardwareAddr) {
	copy(p.buffer[0:6], dstMAC)
	copy(p.buffer[6:12], srcMAC)
}



func (p *IcmpPkt) ipHeader(srcIP, dstIP net.IP) {
	src := srcIP.To4()
	dst := dstIP.To4()
	if src == nil || dst == nil {
		return
	}
	copy(p.buffer[26:30], src)
	copy(p.buffer[30:34], dst)

	ck := Ipv4Sum(p.buffer[14:34])
	binary.BigEndian.PutUint16(p.buffer[24:26], ck)
}



func (p *IcmpPkt) L3Pkt(srcIP, dstIP net.IP) []byte {
	p.ipHeader(srcIP, dstIP)
	return p.buffer[14:42]
}



func (p *IcmpPkt) L2Pkt(
	srcMAC net.HardwareAddr, 
	srcIP  net.IP, 
	dstMAC net.HardwareAddr, 
	dstIP  net.IP,
) []byte {
	p.ipHeader(srcIP, dstIP)
	p.etherHeader(srcMAC, dstMAC)
	return p.buffer[:]
}