package random

import (
	"encoding/binary"
	"fmt"
	"net"
	"offscan/utils"
	"strconv"
	"strings"
)



type Ipv4Iter struct {
    current  uint32
    end      uint32
    total    uint64
    StartU32 uint32
    EndU32   uint32
}



func NewIpv4Iter(cidr string, rangeStr *string) *Ipv4Iter {
    networkU32, broadcastU32 := parseCIDR(cidr)

    usableStart   := networkU32 + 1
    usableEnd     := broadcastU32 - 1
    cidrHasUsable := usableStart <= usableEnd

    var startRange, endRange uint32
    if rangeStr != nil && *rangeStr != "" {
        s := strings.TrimSpace(*rangeStr)
        startRange, endRange, err = parseRange(s, networkU32, broadcastU32, usableStart, usableEnd, cidrHasUsable)
        
		if err != nil {
            return nil, err
        }
    
	} else {
        if cidrHasUsable {
            startRange, endRange = usableStart, usableEnd
        } else {
            startRange, endRange = networkU32, networkU32
        }
    }

    if startRange > endRange {
        utils.Abort("Start IP cannot be greater than end IP")
    }

    total := uint64(endRange - startRange + 1)
    return &Ipv4Iter{
        current:  startRange,
        end:      endRange,
        total:    total,
        StartU32: startRange,
        EndU32:   endRange,
    }
}



func parseCIDR(cidr string) (network, broadcast uint32) {
    parts := strings.Split(cidr, "/")
    
	if len(parts) != 2 {
        utils.Abort(fmt.Sprintf("Invalid CIDR: %s", cidr))
    }

    ip := net.ParseIP(parts[0])
    if ip == nil {
        utils.Abort(fmt.Sprintf("Invalid IP in CIDR '%s'", cidr))
    }
    
	ip = ip.To4()
    if ip == nil {
        utils.Abort(fmt.Sprintf("CIDR '%s' is not IPv4", cidr))
    }

    prefix, err := strconv.Atoi(parts[1])
    if err != nil || prefix < 0 || prefix > 32 {
        utils.Abort(fmt.Sprintf("invalid prefix in CIDR '%s'", cidr))
    }

    ipU32 := binary.BigEndian.Uint32(ip)

    var mask uint32
    if prefix == 0 {
        mask = 0
    } else {
        mask = ^uint32(0) << (32 - uint(prefix))
    }

    network   = ipU32 & mask
    broadcast = network | ^mask
    
	return network, broadcast
}



func parseRange(
	r 			  string, 
	networkU32    uint32, 
	broadcastU32  uint32, 
	usableStart   uint32, 
	usableEnd     uint32, 
	cidrHasUsable bool,
) (uint32, uint32, error) {
    if strings.Contains(r, "*") {
        return parseWildcardRange(r, networkU32, broadcastU32, usableStart, usableEnd, cidrHasUsable)
    }

	return parseSingleIPRange(r)
}



func parseSingleIPRange(ipStr string) (uint32, uint32, error) {
    ip, err := parseIPAddress(ipStr)

	if err != nil {
        return 0, 0, err
    }

	ipU32 := binary.BigEndian.Uint32(ip)
    return ipU32, ipU32, nil
}



func parseWildcardRange(
	rangeStr      string, 
	networkU32, 
	broadcastU32, 
	usableStart, 
	usableEnd     uint32, 
	cidrHasUsable bool,
) (uint32, uint32, error) {
	parts := strings.SplitN(rangeStr, "*", 2)
    
	if len(parts) != 2 {
        return 0, 0, fmt.Errorf("invalid range format: %s", rangeStr)
    }

	startPart := strings.TrimSpace(parts[0])
    endPart   := strings.TrimSpace(parts[1])

    var startIP *uint32
    var startInCidr bool

	if startPart != "" {
        ip, err := parseIPAddress(startPart)

		if err != nil {
            return 0, 0, err
        }

		ipU32      := binary.BigEndian.Uint32(ip)
        startIP     = &ipU32
        startInCidr = cidrHasUsable && ipU32 >= usableStart && ipU32 <= usableEnd
    }

	var endIP *uint32
    var endInCidr bool

	if endPart != "" {
        ip, err := parseIPAddress(endPart)

		if err != nil {
            return 0, 0, err
        }

		ipU32 	 := binary.BigEndian.Uint32(ip)
        endIP     = &ipU32
        endInCidr = cidrHasUsable && ipU32 >= usableStart && ipU32 <= usableEnd
    }

    switch {
    case startPart != "" && endPart != "":
        return *startIP, *endIP, nil

    case startPart != "" && endPart == "":
        if !startInCidr {
    		ipBytes := make([]byte, 4)
    		binary.BigEndian.PutUint32(ipBytes, *startIP)
    		ip := net.IP(ipBytes).To4()
		    	utils.Abort(fmt.Sprintf("start IP %s is outside CIDR range. When using 'IP*', the IP must be within the CIDR", ip.String()))
		}
        
		return *startIP, usableEnd, nil

    case startPart == "" && endPart != "":
        if !endInCidr {
            ip := utils.U32ToIP()
            return 0, 0, fmt.Errorf("end IP %s is outside CIDR range. When using '*IP', the IP must be within the CIDR", ip.String())
        }
        
		return usableStart, *endIP, nil

    case startPart == "" && endPart == "":
        if cidrHasUsable {
            return usableStart, usableEnd, nil
        }
        return usableStart, usableStart, nil

    default:
        return 0, 0, fmt.Errorf("unexpected wildcard parsing")
    }
}

// parseIPAddress converte string em net.IP (IPv4) e valida.
func parseIPAddress(ipStr string) (net.IP, error) {
    ip := net.ParseIP(ipStr)
    if ip == nil {
        return nil, fmt.Errorf("invalid IP address '%s'", ipStr)
    }
    ip4 := ip.To4()
    if ip4 == nil {
        return nil, fmt.Errorf("'%s' is not an IPv4 address", ipStr)
    }
    return ip4, nil
}

// Next retorna o próximo endereço IP e um booleano indicando se existe.
// Quando não há mais IPs, retorna (nil, false).
func (it *Ipv4Iter) Next() (net.IP, bool) {
    if it.current > it.end {
        return nil, false
    }
    // Converte uint32 (big-endian) para 4 bytes e depois para net.IP
    ipBytes := make([]byte, 4)
    binary.BigEndian.PutUint32(ipBytes, it.current)
    ip := net.IP(ipBytes).To4()
    it.current++
    return ip, true
}

// Total retorna o número total de IPs no iterador.
func (it *Ipv4Iter) Total() uint64 {
    return it.total
}

// Reset reinicia o iterador para o primeiro IP.
func (it *Ipv4Iter) Reset() {
    it.current = it.StartU32
}