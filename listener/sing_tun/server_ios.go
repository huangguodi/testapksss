//go:build ios

package sing_tun

import (
	"errors"

	tun "github.com/metacubex/sing-tun"
)

func tunNew(options tun.Options) (tun.Tun, error) {
	if options.FileDescriptor != 0 {
		return tun.New(options)
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
