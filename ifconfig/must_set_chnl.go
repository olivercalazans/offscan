package ifconfig

import (
	"fmt"
	"net"
	"offscan/utils"
)



func MustSetChannel(iface *net.Interface, channel int) {
	if err := TrySetChannel(iface.Name, channel); err != nil {
		utils.Abort(fmt.Sprintf("Unable to set channel %d on interface %s: %s", channel, iface.Name, err))
	}
}