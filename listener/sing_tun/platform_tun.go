package sing_tun

import (
	"errors"
	"net/netip"
	"sync"

	LC "github.com/metacubex/mihomo/listener/config"
)

type PlatformTunOptions struct {
	Name                  string
	MTU                   uint32
	Stack                 string
	AutoRoute             bool
	StrictRoute           bool
	DNSHijack             []string
	DNSServers            []string
	Inet4Address          []netip.Prefix
	Inet6Address          []netip.Prefix
	RouteAddress          []netip.Prefix
	RouteExcludeAddress   []netip.Prefix
	IncludeInterface      []string
	ExcludeInterface      []string
	DisableICMPForwarding bool
}

var (
	platformOpenTunMu      sync.RWMutex
	platformOpenTunHandler func(*PlatformTunOptions) (int, error)
)

func SetPlatformOpenTunHandler(handler func(*PlatformTunOptions) (int, error)) {
	platformOpenTunMu.Lock()
	platformOpenTunHandler = handler
	platformOpenTunMu.Unlock()
}

func ClearPlatformOpenTunHandler() {
	SetPlatformOpenTunHandler(nil)
}

func HasPlatformOpenTunHandler() bool {
	platformOpenTunMu.RLock()
	handler := platformOpenTunHandler
	platformOpenTunMu.RUnlock()
	return handler != nil
}

func openPlatformTun(options *PlatformTunOptions) (int, error) {
	platformOpenTunMu.RLock()
	handler := platformOpenTunHandler
	platformOpenTunMu.RUnlock()
	if handler == nil {
		return 0, errors.New("platform tun handler is not set")
	}
	return handler(options)
}

func newPlatformTunOptions(tunName string, tunMTU uint32, options LC.Tun, routeAddress []netip.Prefix, routeExcludeAddress []netip.Prefix, dnsServerIP []string) *PlatformTunOptions {
	return &PlatformTunOptions{
		Name:                  tunName,
		MTU:                   tunMTU,
		Stack:                 options.Stack.String(),
		AutoRoute:             options.AutoRoute,
		StrictRoute:           options.StrictRoute,
		DNSHijack:             append([]string(nil), options.DNSHijack...),
		DNSServers:            append([]string(nil), dnsServerIP...),
		Inet4Address:          append([]netip.Prefix(nil), options.Inet4Address...),
		Inet6Address:          append([]netip.Prefix(nil), options.Inet6Address...),
		RouteAddress:          append([]netip.Prefix(nil), routeAddress...),
		RouteExcludeAddress:   append([]netip.Prefix(nil), routeExcludeAddress...),
		IncludeInterface:      append([]string(nil), options.IncludeInterface...),
		ExcludeInterface:      append([]string(nil), options.ExcludeInterface...),
		DisableICMPForwarding: options.DisableICMPForwarding,
	}
}
