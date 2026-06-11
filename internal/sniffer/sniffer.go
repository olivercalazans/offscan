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
	"net"
	"sync"

	"golang.org/x/sys/unix"

	"offscan/internal/utils"
)


type Sniffer struct {
	iface      net.Interface
	filter     string
	promisc    bool
	stopChan   chan struct{}
	resultCh   chan []byte
	wg         sync.WaitGroup
	fd         int
	stats      unix.TpacketStats
}



func NewSniffer(
    iface    net.Interface, 
    filter   string, 
    promisc  bool,

) *Sniffer {

    return &Sniffer{
		iface    : iface,
		filter   : filter,
		promisc  : promisc,
		stopChan : make(chan struct{}),
		resultCh : make(chan []byte, 100),
		fd       : -1,
	}
}



func (s *Sniffer) Start() <-chan []byte {
	s.wg.Add(1)
	go s.captureLoop()
	return s.resultCh
}



func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}



func (s *Sniffer) captureLoop() {
	defer s.wg.Done()
	defer close(s.resultCh)

	fd, err := s.initRawSocket()
	if err != nil {
		utils.Abort(fmt.Sprintf("Failed to initialize raw socket: %v", err))
	}
    
	s.fd = fd
	defer unix.Close(s.fd)

	if err := s.configureSocket(); err != nil {
		utils.Abort(fmt.Sprintf("Failed to configure socket parameters: %v", err))
	}

	s.runPollLoop()
}



func (s *Sniffer) initRawSocket() (int, error) {
	protocolNative := int(htons(unix.ETH_P_ALL))

    fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, protocolNative)
	if err != nil {
		return -1, fmt.Errorf("Open raw socket error: %w", err)
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("Set non-blocking error: %w", err)
	}

	return fd, nil
}



func (s *Sniffer) configureSocket() error {
	protocolNative := uint16(htons(unix.ETH_P_ALL))

	sll := &unix.SockaddrLinklayer{
		Protocol : protocolNative,
		Ifindex  : s.iface.Index,
	}

    if err := unix.Bind(s.fd, sll); err != nil {
		return fmt.Errorf("Bind to interface %s failed: %w", s.iface.Name, err)
	}

	if s.promisc {
		mreq := unix.PacketMreq{
			Ifindex : int32(s.iface.Index),
			Type    : unix.PACKET_MR_PROMISC,
		}

        err := unix.SetsockoptPacketMreq(s.fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq)
		if err != nil {
			return fmt.Errorf("Failed to add promisc membership: %w", err)
		}
		
        defer func() {
			_ = unix.SetsockoptPacketMreq(s.fd, unix.SOL_PACKET, unix.PACKET_DROP_MEMBERSHIP, &mreq)
		}()
	}

    if s.filter != "" {
		bytecode, err := s.compileFilter()
		if err != nil {
			return fmt.Errorf("Failed to compile BPF filter '%s': %w", s.filter, err)
		}

		prog := unix.SockFprog{
			Len    : uint16(len(bytecode)),
			Filter : &bytecode[0],
		}

		if err := unix.SetsockoptSockFprog(s.fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
			return fmt.Errorf("Failed to attach BPF filter: %w", err)
		}
	}

	return nil
}



func (s *Sniffer) runPollLoop() {
	pfd := []unix.PollFd{
		{
			Fd     : int32(s.fd),
			Events : unix.POLLIN,
		},
	}

	buf := make([]byte, 65536)

	for {
		select {
		case <-s.stopChan:
			s.collectStats()
			return

		default:
			nReady, err := unix.Poll(pfd, 20)
			if err != nil {
				if err == unix.EINTR { continue }
				return
			}

			if nReady == 0 {
				continue
			}

			n, _, err := unix.Recvfrom(s.fd, buf, 0)
			if err != nil {
				if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
					continue
				}
				return
			}

			packetCopy := make([]byte, n)
			copy(packetCopy, buf[:n])

			select {
			case s.resultCh <- packetCopy:
			case <-s.stopChan:
				s.collectStats()
				return
			}
		}
	}
}



func (s *Sniffer) collectStats() {
    stats, err := unix.GetsockoptTpacketStats(s.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)

	if err == nil {
		s.stats = *stats
	}
}



func (s *Sniffer) Stop() {
	close(s.stopChan)
	s.wg.Wait()

	fmt.Printf("[$] Packets received = %d\n", s.stats.Packets)

	if s.stats.Drops > 0 {
		fmt.Printf("[!] Packets dropped = %d\n", s.stats.Drops)
	}
}