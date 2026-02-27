package main

import (
	"fmt"
	"net"
)

func main() {
	// Nome da interface desejada
	ifaceName := "wlp2s0"

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		fmt.Printf("Erro ao obter interface %s: %v\n", ifaceName, err)
		return
	}

	addrs, err := iface.Addrs()
	if err != nil {
		fmt.Printf("Erro ao obter endereços: %v\n", err)
		return
	}

	fmt.Printf("Interface: %s\n", iface.Name)
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		if ip.To4() != nil { // é IPv4
			fmt.Println("  IPv4:", ip)
		}
	}
}
