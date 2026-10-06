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

package ifmode

import (
	"encoding/binary"
	"syscall"
)


func setLinkUp(ifindex int, up bool) error {
	c, err := newNLConn(syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer c.close()

	// struct ifinfomsg: u8 family; u8 pad; u16 type; int index; u32 flags; u32 change;
	ifinfo    := make([]byte, 16)
	ifinfo[0]  = syscall.AF_UNSPEC
	binary.LittleEndian.PutUint32(ifinfo[4:8], uint32(ifindex))

	var flags uint32
	if up {
		flags = iffUp
	}

	binary.LittleEndian.PutUint32(ifinfo[8:12],  flags) // ifi_flags
	binary.LittleEndian.PutUint32(ifinfo[12:16], iffUp) // ifi_change

	seq, err := c.send(rtmNewlink, nlmFRequest|nlmFAck, ifinfo)
	if err != nil {
		return err
	}
	
	_, err = c.recv(seq, false)
	return err
}