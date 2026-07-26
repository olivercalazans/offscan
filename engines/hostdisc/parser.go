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
	"net"
	"offscan/internal/argparser"
	"offscan/internal/conv"
	"offscan/internal/generators"
	"offscan/internal/netroute"
	"offscan/internal/sysconf"
	"offscan/internal/utils"
	"strings"
)



func DisplayHelp() {
	help := "\n# Host Discovery. E.g., $ sudo ./offscan hdisc <FLAGS>\n\n" +
	        "    -i, --iface <IFACE> : (Optional) Network interface to send packets (default: system default)\n" +
	        "    -r, --range <RANGE> : (Optional) IP range to scan. (*IP or IP*IP or IP*)\n" +
            "                         > *IP   - From the beginning of the subnet until the specified IP\n" +
            "                         > IP*IP - Between two specified IPs\n" +
            "                         > IP*   - From a specified IP until the end of the subnet\n"+
	        "        --arp           : (Optional) Use only/and ARP probes\n"+
	        "        --icmp          : (Optional) Use only/and ICMP probes\n" +
	        "        --tcp           : (Optional) Use only/and TCP probes\n"

	fmt.Println(help)
}



const (
	iface   uint8 = 1
	ipRange uint8 = 2
	arp     uint8 = 3
	icmp    uint8 = 4
	tcp     uint8 = 5
)



func FlagSettings() []argparser.Flag {
	return []argparser.Flag{
		{ID: iface,   Short: "i", Long: "iface", HasValue: true},
		{ID: ipRange, Short: "r", Long: "range", HasValue: true},		
		{ID: arp,     Long: "arp"},
		{ID: icmp,    Long: "icmp"},
		{ID: tcp,     Long: "tcp"},
	}
}



func (hd *hostDiscovery) parseArgs(args []string) {
    flags  := FlagSettings()
	parser := argparser.NewArgParser(flags)
	parser.ParseFlags(args)
	args = nil

	var rangeIP string

	for _, flag := range flags {
		switch flag.ID {
		case iface   : hd.iface = parseIface(flag.ValueStr)
		case ipRange : rangeIP  = flag.ValueStr
		}
	}

	hd.activeIPs  = make(map[[4]byte]hostInfo)
	cidr         := sysconf.MustCIDR(&hd.iface)
	hd.ips        = generators.NewIpv4Iter(cidr, rangeIP)
	hd.myIP       = sysconf.MustIPv4(&hd.iface)
	hd.protoFlags(flags, rangeIP)	
}



func parseIface(str string) net.Interface {
	return utils.Pick(str == "", sysconf.MustDefaultInterface(), conv.MustStrToIface(str))
}



func (hd *hostDiscovery) protoFlags(
	flags    []argparser.Flag,
	rangeIP  string,
) {
	var arpFlag, icmpFlag, tcpFlag bool

	for _, flag := range flags {
		switch flag.ID {
		case arp  : arpFlag  = flag.ValueBool
		case icmp : icmpFlag = flag.ValueBool
		case tcp  : tcpFlag  = flag.ValueBool 
		}
	}

    prots := protocols{
        arp  : true,
        icmp : true,
        tcp  : true,
    }

    if arpFlag || icmpFlag || tcpFlag {
        prots.arp    = arpFlag
        prots.icmp   = icmpFlag
        prots.tcp    = tcpFlag
		hd.protocols = prots
        return
    }
    
    isLocal := true

    if rangeIP != "" {
        for _, ip := range strings.Split(rangeIP, "*") {
            ipv4    := conv.MustStrToIPv4(ip)
            isLocal  = isLocal && netroute.IsLocal(&hd.iface, ipv4)
        }
    }

    hd.protocols = prots
}