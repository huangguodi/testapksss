package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
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
)

type SocketProtector interface {
	ProtectSocket(fd int64, network string, address string) bool
	MarkSocket(fd int64, network string, address string) bool
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

func Start(home, configFileName string) {
	stateMu.Lock()
	defer stateMu.Unlock()

	homeDir = home
	cfgFile = configFileName

	C.SetHomeDir(homeDir)
	C.SetConfig(filepath.Join(homeDir, cfgFile))
	if err := config.Init(C.Path.HomeDir()); err != nil {
		panic(err)
	}

	// iOS 定制优化：强制覆盖部分配置以满足 iOS 扩展的严苛限制
	err := hub.Parse(nil, func(cfg *config.Config) {
		// 1. 关闭 DNS 劫持，减少不必要的内存和处理
		if cfg.General.Tun.Enable {
			cfg.General.Tun.DNSHijack = nil
			cfg.General.Tun.AutoDetectInterface = false
			cfg.General.Tun.AutoRoute = false
			// 2. 强制系统栈，关闭 gvisor 以降低内存占用（25MB 限制），并单线程处理
			cfg.General.Tun.Stack = C.TunSystem
		}
		
		// 3. 关闭非核心组件（例如外部控制器和 UI）
		cfg.Controller.ExternalController = ""
		cfg.Controller.ExternalUI = ""

		// 4. 降低连接池大小 (通过降低并发限制或相关设置)
		cfg.General.TCPConcurrent = false

		// 5. 日志太多会导致扩展被 kill，强制将日志级别设置为 Error 或 Silent
		cfg.General.LogLevel = log.ERROR
		log.SetLevel(log.ERROR)
		
		// 6. 关闭流量统计，以避免内存泄露和并发性能损耗
		statistic.DefaultManager.Disable = true
	})
	if err != nil {
		panic(err)
	}

	isActive = true
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
	cfgFile = configFileName
	C.SetConfig(filepath.Join(homeDir, cfgFile))
	cfg, err := executor.Parse()
	if err != nil {
		panic(err)
	}
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
