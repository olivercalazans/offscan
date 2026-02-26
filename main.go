package main

import (
	"fmt"
	"offscan/iface"
)

func main() {
	ifaceName := "wmon"
	canal := 2 // Canal 11

	err := iface.SetChannel(ifaceName, canal)
	if err != nil {
		fmt.Printf("Erro: %v\n", err)
		return
	}
	fmt.Printf("Sucesso: Canal de %s alterado para %d via syscall!\n", ifaceName, canal)
}
