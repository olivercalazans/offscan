package ifaceinfo

import (
	"fmt"
	"net"
	"os"
)



func IsWireless(iface *net.Interface) bool {
    _, err := os.Stat(fmt.Sprintf("/sys/class/net/%s/wireless", iface.Name))
    return err == nil
}