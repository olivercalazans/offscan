package sockets

import (
	"fmt"
	"net"
	"offscan/utils"

	"golang.org/x/sys/unix"
)



type Layer3Socket struct {
    fd int
}



func New(iface *Iface) *Layer3Socket {
    fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)

	if err != nil {
        utils.Abort(fmt.Sprintf("criar socket raw: %w", err))
    }

    if err := enableIPHdrIncl(fd); err != nil {
        unix.Close(fd)
        utils.Abort(fmt.Sprintf("habilitar IP_HDRINCL: %w", err))
    }

    if err := bindToDevice(fd, iface.Name()); err != nil {
        unix.Close(fd)
        utils.Abort(fmt.Sprintf("vincular à interface: %w", err))
    }

    return &Layer3Socket{fd: fd}
}



func enableIPHdrIncl(fd int) error {
    return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
}



func bindToDevice(fd int, name string) error {
    return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
}



func (s *Layer3Socket) SendTo(packet []byte, dst net.IP) {
    dst4 := dst.To4()
    
    if dst4 == nil {
        utils.Abort(fmt.Sprintf("The destination address is not a IPv4: %v", dst))
    }

    addr := &unix.SockaddrInet4{
        Port: 0,
        Addr: [4]byte{dst4[0], dst4[1], dst4[2], dst4[3]},
    }

    err := unix.Sendto(s.fd, packet, 0, addr)
    
    if err != nil {
        utils.Abort(fmt.Sprintf("Failed to send frame: %w", err))
    }
}



func (s *Layer3Socket) Close() error {
    if s.fd >= 0 {
        err := unix.Close(s.fd)
        s.fd = -1
        return err
    }
    return nil
}