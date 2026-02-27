package sockets

import (
	"fmt"
	"offscan/iface"
	"offscan/utils"

	"golang.org/x/sys/unix"
)



type Layer2Socket struct {
    fd   int
    addr unix.SockaddrLinklayer
}



func New(iface *iface.Iface) *Layer2Socket {
    fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))

	if err != nil {
        utils.Abort(fmt.Sprintf("Failed to create RAW layer 2 socket: %w", err))
    }

    if err := bindToDevice(fd, iface.Name()); err != nil {
        unix.Close(fd)
        utils.Abort(fmt.Sprintf("Failed to bind socket to interface: %w", err))
    }

    if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 1024*1024); err != nil {
        unix.Close(fd)
        utils.Abort(fmt.Sprintf("Failed to configure socket: %w", err))
    }

    addr := unix.SockaddrLinklayer{
        Protocol : htons(unix.ETH_P_ALL),
        Ifindex  : iface.Index(),
        Halen    : 6,
    }

    return &Layer2Socket{fd: fd, addr: addr}
}



func bindToDevice(fd int, name string) error {
    return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
}



func htons(i uint16) uint16 {
    return (i<<8)&0xff00 | i>>8
}



func (s *Layer2Socket) Send(frame []byte) {
    err := unix.Sendto(s.fd, frame, 0, &s.addr)
    
    if err != nil {
        utils.Abort(fmt.Sprintf("Failed to send frame: %w", err))
    }
}



func (s *Layer2Socket) Close() error {
    if s.fd >= 0 {
        err := unix.Close(s.fd)
        s.fd = -1
        return err
    }

    return nil
}