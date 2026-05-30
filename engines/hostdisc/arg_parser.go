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
	"offscan/internal/argparser"
)



type hostDiscParser struct {
    iface  string
    ipRange  string
	arp    bool
    icmp   bool
    tcp    bool
}


const (
	iface   uint8 = 1
	ipRange uint8 = 2
	arp     uint8 = 3
	icmp    uint8 = 4
	tcp     uint8 = 5
)



func newParser() *hostDiscParser {
	return &hostDiscParser{}
}



func (hdp *hostDiscParser) parsePortScanArgs(args []string) {
    flags := []argparser.Flag{
		{ID: iface,   Short: "i", Long: "iface", HasValue: true, Desc: "Network interface to send packets (default: system default)"},
		{ID: ipRange, Short: "r", Long: "range", HasValue: true, Desc: "IP range to scan"},		
		{ID: arp,  Long: "arp",  HasValue: false, Desc: "Use only/and ARP probes"},		
		{ID: icmp, Long: "icmp", HasValue: false, Desc: "Use only/and ICMP probes"},		
		{ID: tcp,  Long: "tcp",  HasValue: false, Desc: "Use only/and TCP probes"},		
	}

	parser := argparser.NewArgParser(flags, args)
	parser.ParseFlags()

	for _, flag := range flags {
		switch flag.ID {
		case iface   : hdp.iface   = flag.ValueStr
		case ipRange : hdp.ipRange = flag.ValueStr
		case arp     : hdp.arp     = flag.ValueBool
		case icmp    : hdp.icmp    = flag.ValueBool
		case tcp     : hdp.tcp     = flag.ValueBool 
		}
	}
}