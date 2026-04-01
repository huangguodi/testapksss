//go:build ios

package sing_tun

import (
	"errors"
	"syscall"

	tun "github.com/metacubex/sing-tun"
)

func tunNew(options tun.Options) (tun.Tun, error) {
	if options.FileDescriptor != 0 {
		t, err := tun.New(options)
		if err != nil {
			return nil, err
		}
		return &closeFdTun{Tun: t, fd: options.FileDescriptor}, nil
	}
	if options.Name != "" {
		return nil, errors.New("ios packet flow mode does not support custom tun device name")
	}
	bridge := getPacketFlowBridge()
	if bridge != nil {
		return newPacketFlowTun(bridge), nil
	}
	return nil, errors.New("packet flow bridge is required on ios")
}

type closeFdTun struct {
	tun.Tun
	fd int
}

func (t *closeFdTun) Close() error {
	err := t.Tun.Close()
	syscall.Close(t.fd)
	return err
}
