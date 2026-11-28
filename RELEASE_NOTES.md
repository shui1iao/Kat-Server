# Kat-Server v0.8.4

Linux 服务端稳定性加固、跨端模块字节级同源统一与边界防御正式发布版（配套 Kat-Client v0.2.38 / Windows Core v0.8.23 与 Kat-Manager v0.1.4）。

## 本版更新
- **TCP 半关闭与 `TCP_INFO` 出站真实载荷看门狗加固**（`internal/kernel/relay.go`、`tcp_progress_linux.go`、`stats/stats.go`）：
  - 修复双向转发在半关闭一侧收到 EOF 后提前中断反向未读完响应流的边界缺陷，并升级统计滑动窗口为无锁环形原子槽位；
  - Linux `TCP_INFO` 空闲看门狗支持内核发送缓冲区排队持续冲刷判定（仅计入真实出站字节 `Bytes_acked + NotSent + Unacked` 增长，剔除零载荷 RTO 重传伪进展），既避免跨洋高延迟大块传输误断活跃长连接，又确保对端黑洞死连接按 `tcp_idle` 准时回收。
- **双端协议与批处理共享包 100% 字节级同源收敛**（`internal/{ss,anytls,udpmmsg}`）：
  - 将 `udpmmsg` 抽离为双端共享包并补齐 `ReadBatch` 空批防御与非 Linux 回退路径单元测试，服务端与客户端 `ss` / `anytls` / `udpmmsg` 生产实现 100% 字节一致。
- **AnyTLS 配置与并发热重载防御加固**（`internal/anytls/config.go`、`internal/kernel/trojan_fallback.go`）：
  - `ValidatePaddingScheme` 拦截负包序号、负数或 `>65535` 长度范围、超界 `stop`、重复整数包序号（如 `"0"` 与 `"00"`/`"+0"`）及科学计数法 `c`；
  - 补齐 API 并发热重载、Unix Socket 权限边界及 Trojan 回落超时/防环路回归测试套件。
