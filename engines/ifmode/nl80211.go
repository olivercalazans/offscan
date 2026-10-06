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
	"fmt"
	"syscall"
)




type nl80211 struct {
	conn  *nlConn
	famID uint16
	ver   uint8
}



func newNL80211() (*nl80211, error) {
	famID, err := resolveGenlFamily(nl80211FamilyName)
	if err != nil {
		return nil, err
	}

	c, err := newNLConn(syscall.NETLINK_GENERIC)
	if err != nil {
		return nil, err
	}

	return &nl80211{conn: c, famID: famID, ver: 1}, nil
}



func (n *nl80211) close() error { return n.conn.close() }



func (n *nl80211) exec(cmd uint8, attrs []byte) error {
	payload  := append(genlHdr(cmd, n.ver), attrs...)
	seq, err := n.conn.send(n.famID, nlmFRequest|nlmFAck, payload)

	if err != nil {
		return err
	}

	_, err = n.conn.recv(seq, true)
	return err
}



func (n *nl80211) deleteInterface(ifindex int) error {
	var attrs []byte
	attrs = putU32Attr(attrs, nl80211AttrIfindex, uint32(ifindex))
	
	if err := n.exec(nl80211CmdDelInterface, attrs); err != nil {
		return fmt.Errorf("nl80211 DEL_INTERFACE: %w", err)
	}
	
	return nil
}



func (n *nl80211) createInterface(wiphy int, name string, iftype uint32) error {
	var attrs []byte
	
	attrs = putU32Attr(attrs, nl80211AttrWiphy, uint32(wiphy))
	attrs = putStringAttr(attrs, nl80211AttrIfname, name)
	attrs = putU32Attr(attrs, nl80211AttrIftype, iftype)
	
	if err := n.exec(nl80211CmdNewInterface, attrs); err != nil {
		return fmt.Errorf("nl80211 NEW_INTERFACE: %w", err)
	}
	
	return nil
}