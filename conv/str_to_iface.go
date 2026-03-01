package conv

import (
	"fmt"
	"net"
	"offscan/utils"
)



func MustGetIface(ifaceName string) *net.Interface {
    iface, err := net.InterfaceByName(ifaceName)
    
	if err != nil {
        utils.Abort(fmt.Sprintf("Erro ao obter interface %s: %v", ifaceName, err))
    }
    
	return iface
}
