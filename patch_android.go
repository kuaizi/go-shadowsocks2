package main

import (
	"fmt"
	"net"
	"syscall"

	"github.com/pkg/errors"
)

func init() {
	net.SetSocketFunc(func(domain int, typ int, proto int) (int, error) {
		fd, err := syscall.Socket(domain, typ, proto)
		if err == nil {
			switch domain {
			case syscall.AF_INET:
				logf("try protect fd=%d", fd)
				err := protectFd(fd)
				if err != nil {
					syscall.Close(fd)
					return 0, errors.Wrap(err, "protect")
				}
			}
		}
		return fd, err
	})
}

func protectFd(fd int) error {
	conn, err := net.Dial("unix", "protect_path")
	if err != nil {
		return errors.Wrap(err, "Dial")
	}
	defer conn.Close()
	protectConn := conn.(*net.UnixConn)
	rights := syscall.UnixRights(fd)
	n, oobn, err := protectConn.WriteMsgUnix(nil, rights, nil)
	if err != nil {
		return errors.Wrap(err, "WriteMsgUnix")
	}
	if oobn != len(rights) {
		return fmt.Errorf("WriteMsgUnix = %d; want %d", oobn, len(rights))
	}
	dummyByte := make([]byte, 1)
	n, err = protectConn.Read(dummyByte)
	if n == 0 && err != nil {
		return errors.Wrap(err, fmt.Sprintf("Read fd=%d", fd))
	}
	ret := dummyByte[0]
	if ret != 0 {
		return fmt.Errorf("protect_path return %d", ret)
	}
	return nil
}
