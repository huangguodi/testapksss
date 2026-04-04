package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/mmdb"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

var (
	stateMu            sync.Mutex
	homeDir            string
	cfgFile            string
	isActive           bool
	socketProtectorMu  sync.RWMutex
	currentProtector   SocketProtector
	socketHookAttached bool
	tunOpenerMu        sync.RWMutex
	currentTunOpener   TunOpener
)

type SocketProtector interface {
	ProtectSocket(fd int64, network string, address string) bool
	MarkSocket(fd int64, network string, address string) bool
}

type TunOpener interface {
	OpenTun(options *TunOptions) int64
}

type TunOptions struct {
	payload tunOptionsPayload
	json    string
}

type tunOptionsPayload struct {
	Name                  string   `json:"name"`
	MTU                   uint32   `json:"mtu"`
	Stack                 string   `json:"stack"`
	AutoRoute             bool     `json:"autoRoute"`
	StrictRoute           bool     `json:"strictRoute"`
	DNSHijack             []string `json:"dnsHijack,omitempty"`
	DNSServers            []string `json:"dnsServers,omitempty"`
	Inet4Address          []string `json:"inet4Address,omitempty"`
	Inet6Address          []string `json:"inet6Address,omitempty"`
	RouteAddress          []string `json:"routeAddress,omitempty"`
	RouteExcludeAddress   []string `json:"routeExcludeAddress,omitempty"`
	IncludeInterface      []string `json:"includeInterface,omitempty"`
	ExcludeInterface      []string `json:"excludeInterface,omitempty"`
	DisableICMPForwarding bool     `json:"disableICMPForwarding"`
}

func SetSocketProtector(protector SocketProtector) {
	socketProtectorMu.Lock()
	currentProtector = protector
	socketProtectorMu.Unlock()

	if protector == nil {
		dialer.DefaultSocketHook = nil
		socketHookAttached = false
		return
	}
	if socketHookAttached {
		return
	}
	dialer.DefaultSocketHook = func(network, address string, conn syscall.RawConn) error {
		var fd int
		err := conn.Control(func(s uintptr) {
			fd = int(s)
		})
		if err != nil {
			return err
		}
		socketProtectorMu.RLock()
		p := currentProtector
		socketProtectorMu.RUnlock()
		if p == nil {
			return nil
		}
		if !p.ProtectSocket(int64(fd), network, address) {
			return fmt.Errorf("protect socket failed: fd=%d network=%s address=%s", fd, network, address)
		}
		_ = p.MarkSocket(int64(fd), network, address)
		return nil
	}
	socketHookAttached = true
}

func ClearSocketProtector() {
	SetSocketProtector(nil)
}

func SetTunOpener(opener TunOpener) {
	tunOpenerMu.Lock()
	currentTunOpener = opener
	tunOpenerMu.Unlock()

	if opener == nil {
		sing_tun.ClearPlatformOpenTunHandler()
		return
	}

	sing_tun.SetPlatformOpenTunHandler(func(options *sing_tun.PlatformTunOptions) (int, error) {
		tunOpenerMu.RLock()
		current := currentTunOpener
		tunOpenerMu.RUnlock()
		if current == nil {
			return 0, errors.New("tun opener is not set")
		}
		fd := current.OpenTun(newTunOptions(options))
		if fd <= 0 {
			return 0, fmt.Errorf("tun opener returned invalid fd: %d", fd)
		}
		return int(fd), nil
	})
}

func ClearTunOpener() {
	SetTunOpener(nil)
}

func applyIOSConfigOverrides(cfg *config.Config) {
	if cfg.General.Tun.Enable {
		cfg.General.Tun.DNSHijack = nil
		cfg.General.Tun.AutoDetectInterface = false
		cfg.General.Tun.Stack = C.TunSystem
		cfg.General.Tun.RecvMsgX = false
		cfg.General.Tun.SendMsgX = false
		cfg.General.Tun.AutoRedirect = false
		cfg.General.Tun.GSO = false
		if cfg.General.Tun.MTU == 0 || cfg.General.Tun.MTU > 1500 {
			cfg.General.Tun.MTU = 1500
		}
		if cfg.General.Tun.UDPTimeout == 0 || cfg.General.Tun.UDPTimeout > 15 {
			cfg.General.Tun.UDPTimeout = 15
		}
	}

	cfg.Controller.ExternalController = ""
	cfg.Controller.ExternalUI = ""

	cfg.General.TCPConcurrent = false
	cfg.General.KeepAliveInterval = 15
	cfg.Profile.StoreSelected = false
	cfg.Profile.StoreFakeIP = false

	if cfg.Experimental == nil {
		cfg.Experimental = &config.Experimental{}
	}
	cfg.Experimental.QUICGoDisableGSO = true

	cfg.General.LogLevel = log.SILENT
	log.SetLevel(log.SILENT)

	statistic.DefaultManager.Disable = true

	cfg.General.GeodataLoader = "memconservative"
	cfg.General.GeoAutoUpdate = false

	cfg.General.Sniffing = false
	if cfg.DNS != nil {
		if cfg.DNS.CacheMaxSize == 0 || cfg.DNS.CacheMaxSize > 512 {
			cfg.DNS.CacheMaxSize = 512
		}
	}
}

func Start(home, configFileName string) {
	stateMu.Lock()
	defer stateMu.Unlock()

	// 限制 Go 运行时内存使用，防止在 iOS 拓展中被 kill (25MB 限制)
	// 预留约 5MB 给 Swift 原生代码，Go 限制在 18MB，同时避免 GC 过于频繁导致发热 (GCPercent=20)
	debug.SetMemoryLimit(18 * 1024 * 1024)
	debug.SetGCPercent(20)
	// iOS 拓展中通常不需要高并发，降低线程数极大地减少线程缓存(mcache)和栈内存占用
	runtime.GOMAXPROCS(1)

	homeDir = home
	cfgFile = configFileName

	C.SetHomeDir(homeDir)
	C.SetConfig(filepath.Join(homeDir, cfgFile))
	if err := config.Init(C.Path.HomeDir()); err != nil {
		log.Errorln("start config init failed: %s", err.Error())
		return
	}

	// iOS 定制优化：强制覆盖部分配置以满足 iOS 扩展的严苛限制
	err := hub.Parse(nil, applyIOSConfigOverrides)
	if err != nil {
		log.Errorln("start config apply failed: %s", err.Error())
		return
	}

	isActive = true

	// 启动定期回收内存任务，避免 iOS 扩展内存膨胀被系统强杀
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if !isActive {
					return
				}
				debug.FreeOSMemory()
			}
		}
	}()
}

func Stop() {
	stateMu.Lock()
	defer stateMu.Unlock()
	if !isActive {
		return
	}
	executor.Shutdown()
	isActive = false
}

func SetLogLevel(level string) {
	logLevel, ok := log.LogLevelMapping[strings.ToLower(level)]
	if !ok {
		return
	}
	log.SetLevel(logLevel)
}

func ForceUpdateConfig(configFileName string) {
	stateMu.Lock()
	defer stateMu.Unlock()
	if homeDir == "" {
		return
	}
	previousCfgFile := cfgFile
	cfgFile = configFileName
	C.SetConfig(filepath.Join(homeDir, cfgFile))
	cfg, err := executor.Parse()
	if err != nil {
		cfgFile = previousCfgFile
		C.SetConfig(filepath.Join(homeDir, cfgFile))
		log.Errorln("force update config failed: %s", err.Error())
		return
	}
	applyIOSConfigOverrides(cfg)
	hub.ApplyConfig(cfg)
}

// SetMode sets the running mode.
// mode: rule, global, direct
func SetMode(mode string) {
	if m, ok := tunnel.ModeMapping[strings.ToLower(mode)]; ok {
		tunnel.SetMode(m)
		statistic.DefaultManager.ClearConnections()
	}
}

func GetMode() string {
	return tunnel.Mode().String()
}

func GetProxies() string {
	all := proxiesWithProviders()
	proxiesPayload := make(map[string]any, len(all))
	for name, proxy := range all {
		data, err := json.Marshal(proxy)
		if err != nil {
			continue
		}
		var item map[string]any
		if err := json.Unmarshal(data, &item); err != nil {
			continue
		}
		if code := proxyCountry(proxy); code != "" {
			item["country"] = code
		}
		proxiesPayload[name] = item
	}
	payload := map[string]any{"proxies": proxiesPayload}
	data, err := json.Marshal(payload)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func ProxyNames() string {
	all := proxiesWithProviders()
	names := make([]string, 0, len(all))
	for name := range all {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func SelectProxy(groupName, proxyName string) bool {
	proxies := tunnel.Proxies()
	group, ok := proxies[groupName]
	if !ok {
		return false
	}

	selector := findSelectable(group)
	if selector == nil && strings.EqualFold(groupName, "GLOBAL") {
		if globalGroup, exists := proxies["GLOBAL"]; exists {
			selector = findSelectable(globalGroup)
		}
	}
	if selector == nil {
		return false
	}
	if err := selector.Set(proxyName); err != nil {
		return false
	}
	statistic.DefaultManager.ClearConnections()
	return true
}

func TrafficUp() int64 {
	up, _ := statistic.DefaultManager.Now()
	return up
}

func (o *TunOptions) JSON() string {
	if o == nil {
		return "{}"
	}
	return o.json
}

func (o *TunOptions) Name() string {
	if o == nil {
		return ""
	}
	return o.payload.Name
}

func (o *TunOptions) MTU() int64 {
	if o == nil {
		return 0
	}
	return int64(o.payload.MTU)
}

func (o *TunOptions) Stack() string {
	if o == nil {
		return ""
	}
	return o.payload.Stack
}

func (o *TunOptions) AutoRoute() bool {
	return o != nil && o.payload.AutoRoute
}

func (o *TunOptions) StrictRoute() bool {
	return o != nil && o.payload.StrictRoute
}

func (o *TunOptions) DNSHijack() string {
	if o == nil {
		return ""
	}
	return strings.Join(o.payload.DNSHijack, ",")
}

func (o *TunOptions) DNSServers() string {
	if o == nil {
		return ""
	}
	return strings.Join(o.payload.DNSServers, ",")
}

func (o *TunOptions) Inet4Address() string {
	if o == nil {
		return ""
	}
	return strings.Join(o.payload.Inet4Address, ",")
}

func (o *TunOptions) Inet6Address() string {
	if o == nil {
		return ""
	}
	return strings.Join(o.payload.Inet6Address, ",")
}

func (o *TunOptions) RouteAddress() string {
	if o == nil {
		return ""
	}
	return strings.Join(o.payload.RouteAddress, ",")
}

func (o *TunOptions) RouteExcludeAddress() string {
	if o == nil {
		return ""
	}
	return strings.Join(o.payload.RouteExcludeAddress, ",")
}

func (o *TunOptions) IncludeInterface() string {
	if o == nil {
		return ""
	}
	return strings.Join(o.payload.IncludeInterface, ",")
}

func (o *TunOptions) ExcludeInterface() string {
	if o == nil {
		return ""
	}
	return strings.Join(o.payload.ExcludeInterface, ",")
}

func (o *TunOptions) DisableICMPForwarding() bool {
	return o != nil && o.payload.DisableICMPForwarding
}

func newTunOptions(options *sing_tun.PlatformTunOptions) *TunOptions {
	payload := tunOptionsPayload{
		Name:                  options.Name,
		MTU:                   options.MTU,
		Stack:                 options.Stack,
		AutoRoute:             options.AutoRoute,
		StrictRoute:           options.StrictRoute,
		DNSHijack:             append([]string(nil), options.DNSHijack...),
		DNSServers:            append([]string(nil), options.DNSServers...),
		Inet4Address:          prefixesToStrings(options.Inet4Address),
		Inet6Address:          prefixesToStrings(options.Inet6Address),
		RouteAddress:          prefixesToStrings(options.RouteAddress),
		RouteExcludeAddress:   prefixesToStrings(options.RouteExcludeAddress),
		IncludeInterface:      append([]string(nil), options.IncludeInterface...),
		ExcludeInterface:      append([]string(nil), options.ExcludeInterface...),
		DisableICMPForwarding: options.DisableICMPForwarding,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		data = []byte("{}")
	}
	return &TunOptions{
		payload: payload,
		json:    string(data),
	}
}

func prefixesToStrings(prefixes []netip.Prefix) []string {
	if len(prefixes) == 0 {
		return nil
	}
	items := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		items = append(items, prefix.String())
	}
	return items
}

func TrafficDown() int64 {
	_, down := statistic.DefaultManager.Now()
	return down
}

func TrafficTotalUp() int64 {
	up, _ := statistic.DefaultManager.Total()
	return up
}

func TrafficTotalDown() int64 {
	_, down := statistic.DefaultManager.Total()
	return down
}

func TestLatency(proxyName string) string {
	proxy, ok := proxiesWithProviders()[proxyName]
	if !ok {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	delay, err := proxy.URLTest(ctx, C.DefaultTestURL, nil)
	if err != nil || delay == 0 {
		return ""
	}
	return strconv.FormatUint(uint64(delay/10), 10)
}

func Version() string {
	return C.Version
}

func proxiesWithProviders() map[string]C.Proxy {
	all := make(map[string]C.Proxy)
	for name, proxy := range tunnel.Proxies() {
		all[name] = proxy
	}
	for _, provider := range tunnel.Providers() {
		for _, proxy := range provider.Proxies() {
			all[proxy.Name()] = proxy
		}
	}
	return all
}

func findSelectable(proxy C.Proxy) outboundgroup.SelectAble {
	current := proxy
	for i := 0; i < 16 && current != nil; i++ {
		if selectable, ok := any(current).(outboundgroup.SelectAble); ok {
			return selectable
		}
		if adapter := current.Adapter(); adapter != nil {
			if selectable, ok := adapter.(outboundgroup.SelectAble); ok {
				return selectable
			}
		}
		next := current.Unwrap(nil, false)
		if next == nil || next == current {
			break
		}
		current = next
	}
	return nil
}

func proxyCountry(proxy C.Proxy) string {
	host, err := parseProxyHost(proxy.Addr())
	if err != nil || host == "" {
		return ""
	}

	if ip := net.ParseIP(host); ip != nil {
		return lookupCountryByIP(ip)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return ""
	}
	for _, ip := range ips {
		if ip == nil || ip.To16() == nil {
			continue
		}
		if code := lookupCountryByIP(ip); code != "" {
			return code
		}
	}
	return ""
}

func lookupCountryByIP(ip net.IP) string {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return ""
	}
	codes := mmdb.IPInstance().LookupCode(addr.AsSlice())
	if len(codes) == 0 || codes[0] == "" {
		return ""
	}
	return strings.ToUpper(codes[0])
}

func parseProxyHost(addr string) (string, error) {
	if addr == "" {
		return "", nil
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host, nil
	}
	if strings.Count(addr, ":") > 1 && !strings.Contains(addr, "]") {
		return addr, nil
	}
	return addr, nil
}
