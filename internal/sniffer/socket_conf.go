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
 * along with this program.  If not, see <https://gnu.org>.
 */

package sniffer

import (
	"fmt"

	"golang.org/x/sys/unix"
)



func htons(i uint16) uint16 {
	return (i << 8) & 0xff00 | i>>8
}



func (s *Sniffer) initRawSocket() (error) {
	protocol := int(htons(unix.ETH_P_ALL))
	fd, err  := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, protocol)

	if err != nil {
		s.fd = -1
		return fmt.Errorf("socket: %w", err)
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		s.fd = -1
		return fmt.Errorf("set nonblock: %w", err)
	}

	s.fd = fd
	return nil
}



func (s *Sniffer) configureSocket() error {
	if err := s.bindToInterface();   err != nil { return err }
	if err := s.enablePromiscuous(); err != nil { return err }
	if err := s.attachFilter();      err != nil { return err }

	return nil
}



func (s *Sniffer) bindToInterface() error {
	sll := &unix.SockaddrLinklayer{
		Protocol : uint16(htons(unix.ETH_P_ALL)),
		Ifindex  : s.iface.Index,
	}

	if err := unix.Bind(s.fd, sll); err != nil {
		return fmt.Errorf("bind to %s: %w", s.iface.Name, err)
	}

	return nil
}



func (s *Sniffer) enablePromiscuous() error {
	if !s.promisc { return nil }

	mreq := unix.PacketMreq{
		Ifindex : int32(s.iface.Index),
		Type	: unix.PACKET_MR_PROMISC,
	}

	err := unix.SetsockoptPacketMreq(s.fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq)
	if err != nil {
		return fmt.Errorf("add promisc: %w", err)
	}

	s.promiscMreq = &mreq
	return nil
}



func (s *Sniffer) disablePromiscuous() {
	if !s.promisc || s.promiscMreq == nil || s.fd == -1 {
		return
	}

	err := unix.SetsockoptPacketMreq(s.fd, unix.SOL_PACKET, unix.PACKET_DROP_MEMBERSHIP, s.promiscMreq)
	if err != nil {
		fmt.Printf("[!] Unable to disable promisc: %v\n", err)
	}

	s.promiscMreq = nil
}



func (s *Sniffer) attachFilter() error {
	if s.filter == "" { return nil }
	
	bytecode, err := s.compileFilter()

	if err != nil {
		return fmt.Errorf("compile filter: %w", err)
	}

	prog := unix.SockFprog{
		Len    : uint16(len(bytecode)),
		Filter : &bytecode[0],
	}

	if err := unix.SetsockoptSockFprog(s.fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		return fmt.Errorf("attach filter: %w", err)
	}

	return nil
}



func (s *Sniffer) setupEpoll() error {
	// Create eventfd for stop signal
	efd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		return fmt.Errorf("eventfd: %w", err)
	}
	s.stopEventFd = efd

	// Create epoll fd
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		unix.Close(efd)
		return fmt.Errorf("epoll_create1: %w", err)
	}
	s.epollFd = epfd

	// Add raw socket to epoll
	ev := unix.EpollEvent{
		Events : unix.EPOLLIN,
		Fd     : int32(s.fd),
	}

	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, s.fd, &ev); err != nil {
		unix.Close(epfd)
		unix.Close(efd)
		return fmt.Errorf("epoll_ctl add socket: %w", err)
	}

	// Add eventfd to epoll
	ev.Fd     = int32(s.stopEventFd)
	ev.Events = unix.EPOLLIN

	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, s.stopEventFd, &ev); err != nil {
		unix.Close(epfd)
		unix.Close(efd)
		return fmt.Errorf("epoll_ctl add eventfd: %w", err)
	}

	return nil
}