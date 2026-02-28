package ifconfig

import (
	"fmt"
	"offscan/utils"
)



func MustSetChannel(ifaceName string, channel int) {
	if err := TrySetChannel(ifaceName, channel); err != nil {
		utils.Abort(fmt.Sprintf("Unable to set channel %d on interface %s: %s", channel, ifaceName, err))
	}
}