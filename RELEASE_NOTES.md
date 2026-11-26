# Kat-Server v0.8.3

Linux 服务端极限性能优化正式发布版（配套 Kat-Client v0.2.34 / Windows Core v0.8.21 与 Kat-Manager v0.1.3）。

## 本版更新
- **Linux UDP 全链路批处理 + GSO / GRO**（`internal/kernel/udp_mmsg_linux.go`、`ss_udp.go`、`udp.go`、`internal/anytls/uot.go`）：
  - 基于 Go netpoller 实现零分配 Linux `recvmmsg` / `sendmmsg` 批量收发与缓冲池复用，支持同目标等长包 scatter-gather `UDP_SEGMENT` (GSO) 合并发送与 `UDP_GRO` 超级包原地零拷贝拆分；非 Linux / 32 位平台与旧内核自动无损降级。
  - SS2022 UDP 稳态无队列直通批转发 + AnyTLS UoT 多包聚合写帧，4 核满载下全栈 SS2022 UDP 4 并发达 463 Mbps（较旧版提速 2.3×、CPU 降 60%），AnyTLS UoT 达 441 Mbps（零丢包）。
- **Linux 直通 TCP `splice(2)` 解包修复**（`internal/kernel/relay.go`）：
  - 修复生产默认 `tcp_idle > 0` 下 `*activityStream` 包装导致 `net.TCPConn` 断言失效退化为用户态拷贝的问题；解包并按 256 KiB 分块刷新活跃时间与流量统计，直通 SOCKS5 TCP 单流由 8.25 提升至 23.3 Gbps、8 流由 19.6 提升至 35.2 Gbps（CPU 降 83%）。
- **AnyTLS 与 SS2022 热路径精简**（`internal/anytls/*`、`internal/ss/*`）：优化地址编解码、SS2022 下行与紧凑 salt 回收热路径，压低高并发 CPU 与内存分配。
