package iface

import (
	"fmt"
	"net"
	"os"
	"strings"
)



func State(iface *net.Interface) (string, error) {
    data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/operstate", iface.Name))

	if err != nil {
        return "", err
    }

	return strings.ToUpper(strings.TrimSpace(string(data))), nil
}