/*
 * Copyright (C) 2025 Oliver R. Calazans Jeronimo
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org>.
 */

package ifconfig

import (
	"fmt"
	"net"
	"offscan/utils"
	"syscall"
	"unsafe"
)



const (
	SIOCSIWFREQ = 0x8B04 // Set frequency/channel
)



type iwreq struct {
	ifrName [16]byte
	ifrData [16]byte
}



type iw_freq struct {
	m     int32
	e     int16
	i     uint8
	flags uint8
}



func TrySetChannel(iface *net.Interface, channel int) error {
	validateChannel(channel)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	var wrq iwreq
	copy(wrq.ifrName[:], []byte(iface.Name))

	freq := iw_freq{
		m: int32(channel),
		e: 0,
		i: 0,
	}

	*(*iw_freq)(unsafe.Pointer(&wrq.ifrData[0])) = freq

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(SIOCSIWFREQ), uintptr(unsafe.Pointer(&wrq)))

	if errno != 0 {
		return fmt.Errorf("ioctl error: %v", errno)
	}

	return nil
}



func MustSetChannel(iface *net.Interface, channel int) {
	if err := TrySetChannel(iface, channel); err != nil {
		utils.Abort(fmt.Sprintf("Unable to set channel %d on interface %s: %s", channel, iface.Name, err))
	}
}