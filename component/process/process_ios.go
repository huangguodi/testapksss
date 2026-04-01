//go:build ios

package process

import "net/netip"

func findProcessName(network string, ip netip.Addr, srcPort int) (uint32, string, error) {
	return 0, "", ErrPlatformNotSupport
}
