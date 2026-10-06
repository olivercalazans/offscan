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
	"errors"
	"fmt"
	"syscall"
)



type nlConn struct {
	fd  int
	seq uint32
}



func newNLConn(proto int) (*nlConn, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, proto)
	
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	
	addr := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	
	return &nlConn{fd: fd}, nil
}



func (c *nlConn) close() error { return syscall.Close(c.fd) }



func (c *nlConn) send(msgType, flags uint16, payload []byte) (uint32, error) {
	c.seq++
	seq := c.seq
	hdr := make([]byte, 16)
	
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(16+len(payload)))
	binary.LittleEndian.PutUint16(hdr[4:6], msgType)
	binary.LittleEndian.PutUint16(hdr[6:8], flags)
	binary.LittleEndian.PutUint32(hdr[8:12], seq)

	msg := append(hdr, payload...)
	dst := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	
	if err := syscall.Sendto(c.fd, msg, 0, dst); err != nil {
		return 0, err
	}
	
	return seq, nil
}



func (c *nlConn) recv(seq uint32, skipGenl bool) ([]byte, error) {
	buf := make([]byte, 8192)

	for {
		n, _, err := syscall.Recvfrom(c.fd, buf, 0)

		if err != nil {
			return nil, err
		}

		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}

		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}

			switch m.Header.Type {
			case syscall.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return nil, errors.New("netlink: truncated error")
				}

				code := int32(binary.LittleEndian.Uint32(m.Data[0:4]))
				if code == 0 {
					return nil, nil // ACK OK
				}

				return nil, syscall.Errno(-code)

			case syscall.NLMSG_DONE:
				return nil, nil

			default:
				data := m.Data
				if skipGenl {
					if len(data) < 4 {
						return nil, errors.New("genl: short header")
					}
					data = data[4:]
				}

				return data, nil
			}
		}
	}
}



func resolveGenlFamily(name string) (uint16, error) {
	c, err := newNLConn(syscall.NETLINK_GENERIC)
	if err != nil {
		return 0, err
	}
	defer c.close()

	payload := genlHdr(ctrlCmdGetFamily, 1)
	payload  = putStringAttr(payload, ctrlAttrFamilyName, name)

	seq, err := c.send(genlIDCtrl, nlmFRequest, payload)
	if err != nil {
		return 0, err
	}

	data, err := c.recv(seq, true)
	if err != nil {
		return 0, err
	}

	if data == nil {
		return 0, fmt.Errorf("genl: family %q not found", name)
	}

	attrs     := parseAttrs(data)
	idBuf, ok := attrs[ctrlAttrFamilyID]

	if !ok || len(idBuf) < 2 {
		return 0, fmt.Errorf("genl: FAMILY_ID attribute missing for %q", name)
	}

	return binary.LittleEndian.Uint16(idBuf), nil
}



func parseAttrs(buf []byte) map[uint16][]byte {
	out := make(map[uint16][]byte)
	
	for len(buf) >= 4 {
		alen := int(binary.LittleEndian.Uint16(buf[0:2]))
		atyp := binary.LittleEndian.Uint16(buf[2:4])
		
		if alen < 4 || alen > len(buf) {
			break
		}
		
		out[atyp&0x3fff] = buf[4:alen]
		buf = buf[align4(alen):]
	}

	return out
}