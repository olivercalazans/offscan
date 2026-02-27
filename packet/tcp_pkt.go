package packet

import (
	"encoding/binary"
	"net"
)



type TcpPkt struct {
    buffer [54]byte
}



func NewTcpPkt() *TcpPkt {
    t := &TcpPkt{}
	buildFixed(t)
    return t
}



func buildFixed(t *TcpPkt) {
	// Ethernet header (0 - 14)
	binary.BigEndian.PutUint16(t.buffer[12:14], 0x0800)

	// IP header (14 - 34)
    t.buffer[14] = (4 << 4) | 5
    t.buffer[15] = 0
    binary.BigEndian.PutUint16(t.buffer[16:18], 40)
    binary.BigEndian.PutUint16(t.buffer[18:20], 0x1234)
    binary.BigEndian.PutUint16(t.buffer[20:22], 0x4000)
    t.buffer[22] = 64 
    t.buffer[23] = 6

	// TCP header (34 - 54)
    binary.BigEndian.PutUint32(t.buffer[38:42], 1)
    binary.BigEndian.PutUint32(t.buffer[42:46], 0)
    t.buffer[46] = 5 << 4
    t.buffer[47] = 0x02
    binary.BigEndian.PutUint16(t.buffer[48:50], 64240)
    binary.BigEndian.PutUint16(t.buffer[52:54], 0)
}




func (t *TcpPkt) etherHeader(srcMac, dstMac net.HardwareAddr) {
    copy(t.buffer[0:6], dstMac[:])
    copy(t.buffer[6:12], srcMac[:])

}



func (t *TcpPkt) ipHeader(srcIP, dstIP net.IP) {
    src := srcIP.To4()
    dst := dstIP.To4()
    copy(t.buffer[26:30], src)
    copy(t.buffer[30:34], dst)

    cksum := Ipv4Sum(t.buffer[14:34])
    binary.BigEndian.PutUint16(t.buffer[24:26], cksum)
}



func (t *TcpPkt) tcpHeader(
	srcIP   net.IP, 
	srcPort uint16, 
	dstIP   net.IP, 
	dstPort uint16,
) {
    binary.BigEndian.PutUint16(t.buffer[34:36], srcPort)
    binary.BigEndian.PutUint16(t.buffer[36:38], dstPort)
    binary.BigEndian.PutUint16(t.buffer[50:52], 0)

    cksum := TcpUdpSum(t.buffer[34:54], srcIP, dstIP, 6)
    binary.BigEndian.PutUint16(t.buffer[50:52], cksum)
}



func (t *TcpPkt) L3Pkt(
	srcIP   net.IP, 
	srcPort uint16, 
	dstIP   net.IP, 
	dstPort uint16,
) []byte {
    t.tcpHeader(srcIP, srcPort, dstIP, dstPort)
    t.ipHeader(srcIP, dstIP)
    return t.buffer[14:54]
}



func (t *TcpPkt) L2Pkt(
	srcMac  net.HardwareAddr, 
	srcIP   net.IP, 
	srcPort uint16, 
	dstMac  net.HardwareAddr,
	dstIP   net.IP, 
	dstPort uint16,
) []byte {
    t.tcpHeader(srcIP, srcPort, dstIP, dstPort)
    t.ipHeader(srcIP, dstIP)
    t.etherHeader(srcMac, dstMac)
    return t.buffer[:]
}