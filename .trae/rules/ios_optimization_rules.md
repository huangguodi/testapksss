# iOS Network Extension 开发与优化铁律 (针对 Mihomo 内核)

在对本项目进行修改或增加新特性时，**必须**严格遵守以下针对 iOS 扩展 (Network Extension) 的内存和资源限制规则。由于 iOS 对扩展的内存限制极度严苛（通常为 15MB 左右），稍微不慎就会导致进程被 Jetsam 强杀。

## 1. 内存管理与垃圾回收 (GC) 限制
- **硬性上限：** 必须使用 `debug.SetMemoryLimit` 将 Go 运行时的内存强制压制在较低水位（建议 15~18MB），确保给 Swift 原生代码预留足够的内存。
- **主动回收：** 必须通过后台定时器定期调用 `debug.FreeOSMemory()`，主动将不用的内存归还给操作系统。
- **并发约束：** 为了减少 `mcache` (线程本地缓存) 和 Goroutine 栈的开销，在 iOS 环境中应使用 `runtime.GOMAXPROCS(1)` 限制为单核。
- **减少对象分配：** 高频创建的大块对象（例如 1500 byte 的数据包 Slice），**严禁每次 alloc**，必须使用 `sync.Pool` 进行复用。

## 2. TUN 网络通道配置
- **单队列读写：** iOS 不支持多队列 TUN。必须禁用相关并发配置（如 `RecvMsgX = false`, `SendMsgX = false`）。
- **Packet Information (PI) 模式：** 必须处理 4 字节的 PI 头。如果通过 FileDescriptor (fd) 注入，确保 `sing-tun` 或者其他底层库能够正确读取前 4 个字节，否则会解析失败。
- **防文件描述符 (fd) 泄漏：** iOS 多次开关拓展时不会自动释放 fd，拓展销毁时必须在 `Close()` 生命周期中显式调用 `syscall.Close(fd)`。
- **小数据包：** 将 TUN 的 `MTU` 强制设置为 `1500`，减小单包占用，严禁启用大包优化特性（如 `GSO = false` 和 `QUICGoDisableGSO = true`）。

## 3. 并发测速与网络组件降级
- **控制并发数量：** 在健康检查（URLTest / Fallback）和多节点负载均衡中，必须限制并发数量。例如，将 `errgroup` 的限制设定为较小的值（如 `3`），防止瞬间产生数百个连接引发 OOM。
- **连接存活时间：** TCP 保活 (`KeepAliveInterval`) 和 UDP 超时 (`UDPTimeout`) 必须缩短（建议 15 秒内），尽快释放空闲连接和相关结构体。
- **限制缓存大小：** 必须限制如 DNS 的 `CacheMaxSize` 和 `LoadBalance` 中的 LRU 缓存，避免由于长期运行堆积历史记录。

## 4. 后台 IO 与其他高消耗操作
- **彻底关闭日志：** 日志的字符串拼接与输出极占内存。必须将日志级别设置为 `SILENT`。
- **关闭自动更新：** 必须关闭后台自动更新（如 GeoData 自动下载），并强制使用最省内存的加载模式 (`memconservative`)。
- **关闭磁盘持久化：** 禁用 `StoreSelected` 和 `StoreFakeIP` 等写入操作，防止临时 JSON 序列化带来的内存飙升。
- **关闭流量嗅探：** `Sniffing` 会在内存中缓冲大量数据包用于协议分析，必须关闭以节省 CPU 和内存。

## 5. 编译与打包
- 所有针对 iOS 的专属优化和存根，应当使用 `//go:build ios` 约束。
- 编译生成动态库/静态库时，请务必启用编译标签 `-tags with_low_memory`。