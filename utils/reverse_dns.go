package utils

import (
	"net"
	"strings"
)



func GetHostName(ip string) string {
    names, err := net.LookupAddr(ip)

	if err != nil || len(names) < 1 {
        return "Unknown"
    }

    hostname := names[0]
    hostname  = strings.TrimSuffix(hostname, ".")
    hostname  = strings.TrimSuffix(hostname, ".lan")

    return hostname
}