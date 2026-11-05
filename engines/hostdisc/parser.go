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

package hostdisc

import (
	"fmt"
	"offscan/internal/argparser"
	"offscan/internal/generators"
	"offscan/internal/models"
	"offscan/internal/netroute"
	"offscan/internal/sysconf"
	"offscan/internal/utils"
	"strings"
)



func DisplayHelp() {
	help := "\n### HOST DISCOVERY\n\n" + 
	        "    E.g., $ sudo ./offscan hdisc <FLAGS>\n\n" +
	        "    -i, --iface <IFACE> : (Optional) Network interface to send packets (default: system default)\n" +
	        "    -r, --range <RANGE> : (Optional) IP range to scan. (+IP or IP+IP or IP+)\n" +
            "                         > +IP   - From the beginning of the subnet until the specified IP\n" +
            "                         > IP+IP - Between two specified IPs\n" +
            "                         > IP+   - From a specified IP until the end of the subnet\n"+
	        "        --arp           : (Optional) Use only/and ARP probes\n"+
	        "        --icmp          : (Optional) Use only/and ICMP probes\n" +
	        "        --tcp           : (Optional) Use only/and TCP probes\n"

	fmt.Println(help)
}



type hostDiscoveryParser struct {
	engine  	  *hostDiscovery
	parser        *argparser.ArgParser
	icmpExplicit   bool
	tcpExplicit    bool
}



func (hd *hostDiscovery) parseArgs(args []string) {
	hdp := hostDiscoveryParser{}
	
	hdp.engine = hd
	hdp.parser = argparser.NewArgParser(args)
	
	hdp.parseIface()
	hdp.parseARP()
	hdp.parseICMP()
	hdp.parseTCP()
	
	rangeIP := hdp.parseRange()
	cidr    := sysconf.MustCIDR(&hd.iface)
	hd.ips   = generators.NewIpv4Iter(cidr, rangeIP)
	
	hdp.validProtocols(rangeIP)

	hdp.parser.AbortIfHasError()
	
	hd.myIP        = sysconf.MustIPv4(&hd.iface)
	hd.activeHosts = models.NewSet[hostInfo](20)
	hd.rounds     = 2
}



func (hdp *hostDiscoveryParser) parseIface() {
	arg := argparser.Argument{ Long: "--iface", Short: "-i", Required: false }

	iface, ok := hdp.parser.Iface(&arg)

	if !ok {
		hdp.engine.iface = sysconf.MustDefaultInterface()
		return
	}
	
	hdp.engine.iface = iface
}



func (hdp *hostDiscoveryParser) parseRange() string {
	arg := argparser.Argument{ Long: "--range", Short: "-r", Required: false }

	str, _ := hdp.parser.String(&arg)
	return str
}



func (hdp *hostDiscoveryParser) parseARP() {
	args := argparser.Argument{ Long: "--arp", Short: "", Required: false }
	hdp.engine.protocols.arp = hdp.parser.Bool(&args)
}



func (hdp *hostDiscoveryParser) parseICMP() {
	args := argparser.Argument{ Long: "--icmp", Short: "", Required: false }
	
	hdp.icmpExplicit 		  = hdp.parser.Bool(&args)
	hdp.engine.protocols.icmp = hdp.icmpExplicit
}



func (hdp *hostDiscoveryParser) parseTCP() {
	args := argparser.Argument{ Long: "--tcp", Short: "", Required: false }
	
	hdp.tcpExplicit          = hdp.parser.Bool(&args)
	hdp.engine.protocols.tcp = hdp.tcpExplicit
}



func (hdp *hostDiscoveryParser) validProtocols(rangeIP string) {
    hd := hdp.engine

    if !hd.protocols.arp && !hd.protocols.icmp && !hd.protocols.tcp {
        hd.protocols.arp  = true
        hd.protocols.icmp = true
        hd.protocols.tcp  = true
    }

    isLocal := rangeIP == "" || hdp.isRangeLocal(rangeIP)

    if !isLocal {
        return
    }

    hd.protocols.arp = true
	
    if !hdp.icmpExplicit { hd.protocols.icmp = false }
    if !hdp.tcpExplicit  { hd.protocols.tcp  = false }
}



func (hdp *hostDiscoveryParser) isRangeLocal(rangeIP string) bool {
	isLocal := true

    for ip := range strings.SplitSeq(rangeIP, "+") {
        ipv4 := models.MustStrToIPv4(ip)
		
		value, err := netroute.IsLocal(&hdp.engine.iface, ipv4)
		if err != nil {
			utils.Abort(err.Error())
		}
        
		isLocal = isLocal && value
    }

	return isLocal
}
