package ifconfig

import (
	"fmt"
	"offscan/utils"
)



func validateChannel(channel int) {
	if channel < 1 || channel > 165 {
		utils.Abort(fmt.Sprintf("The channel must be between 1 and 165 (input: %d)", channel))
	}
}