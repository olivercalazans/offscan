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

package sysconf

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)


func GetIfaceLinkType(iface *net.Interface) (int, error) {
    fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)

	if err != nil {
        return 0, err
    }
    defer unix.Close(fd)

    var ifreq struct {
        name [16]byte
        data [32]byte
    }

	copy(ifreq.name[:], []byte(iface.Name))

    _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCGIFHWADDR, uintptr(unsafe.Pointer(&ifreq)))
    
	if errno != 0 {
        return 0, errno
    }

    arpType := int(ifreq.data[0]) | (int(ifreq.data[1]) << 8)

    switch arpType {
    case unix.ARPHRD_ETHER:  // 1
        return 1, nil        // DLT_EN10MB    
	case unix.ARPHRD_IEEE80211:  // 801
        return 105, nil 		 // DLT_IEEE802_11
	case unix.ARPHRD_IEEE80211_RADIOTAP:  // 803
        return 127, nil 				  // DLT_IEEE802_11_RADIO
    default:
        return 0, fmt.Errorf("unsupported ARPHRD type %d", arpType)
    }
}