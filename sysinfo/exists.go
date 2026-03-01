package sysinfo

import (
	"net"
)



func IfaceExist(name string) bool {
    _, err := net.InterfaceByName(name)
    
	if err != nil {
        return false
    }

    return true
}