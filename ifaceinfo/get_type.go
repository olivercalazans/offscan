package ifaceinfo

import (
	"fmt"
	"net"
	"os"
	"strings"
)



func Type(iface *net.Interface) string {
    if IsWireless(iface) {
        return "Wireless"
    }

	data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/type", iface.Name))

	if err != nil {
        return "Unknown"
    }

	typ := strings.TrimSpace(string(data))

	switch typ {
    	case "1":   return "Ethernet"
    	case "772": return "Loopback"
    	default:    return "Type-" + typ
    }
}