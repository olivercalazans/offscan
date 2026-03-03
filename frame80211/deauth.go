package frame80211

import (
	"encoding/binary"
	"net"
)

type Mac = net.HardwareAddr



type Deauth struct {
	buffer [38]byte
}



func NewDeauthFrame(bssid Mac) *Deauth {
	deauth := Deauth{}
	buildFixed(deauth.buffer[:], bssid)
	
	return &deauth
}



func buildFixed(buffer []byte, bssid Mac) {        
	MinimalRariotapHeader(buffer[:12])

    buffer[12] = 0xC0
    buffer[13] = 0x00
    buffer[14] = 0x3a
    buffer[15] = 0x01

    copy(buffer[28:34], bssid)

    buffer[36] = 0x07
    buffer[37] = 0x00
}



func (d *Deauth) Frame(srcMac, dstMac Mac, seq uint16) [] byte {
    copy(d.buffer[16:22], dstMac)
    copy(d.buffer[22:28], srcMac)

    seqCtrl := uint16((seq & 0x0FFF) << 4)
    binary.LittleEndian.PutUint16(d.buffer[34:36], seqCtrl)
    
    return d.buffer[:]
}