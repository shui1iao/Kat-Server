# Kat-Server v0.8.1

仅发布，不自动部署或升级现有服务。命令 `kat`、Go 模块路径和 Linux 附件命名契约不变。同提交对应的独立 Windows 客户端内核发布于 `windows-core-v0.8.1`（`make_latest=false`）。

## 本版变化
- **服务端与客户端职责分离精简**：`Kat-Server` 收敛为纯正式入站 + 直连转发（`direct`）服务端内核，移除实验性协议（VLESS/REALITY/Vision/XUDP/XHTTP/gRPC/WebSocket/HTTPUpgrade、Snell）以及仅客户端使用的代理出站、策略组、订阅 provider、路由规则集（SRS/MRS/GeoIP/GeoSite/ASN）与协议嗅探代码及对应第三方依赖；保留 SOCKS5、Shadowsocks 2017/2022、Trojan、AnyTLS 五类正式入站，以及直连 DNS、TLS/ACME/TFO、入站安全封禁、流量统计、管理 API 与原子热重载。
- **配置边界显式校验**：服务端配置若包含客户端专属字段（`outbounds`、`groups`、`providers`、`routing`、`rule_sets`、`geoip`、`geosite`、`asn` 或入站 `sniff`），`kat check`、启动与重载均明确拒绝报错，不静默忽略。
- **继承 v0.8.0 传输稳定性修复**：保持 TCP 转发半关闭静默收敛（`ECONNABORTED` 与单向正常 EOF 后另一方向 `quietFailure` 不误计失败）、AnyTLS 会话授权与热重载原子性。
- **Windows Core `v0.8.1`（`windows-core-v0.8.1` Release）**：同步完成协议精简、规则集内存结构优化（紧凑后缀表 + 规则靶向编译）、HTTP 探测/订阅桥空闲连接回收、已完成 TUN 恢复账本 LUID/PID 复用退休修复，以及 AnyTLS 复用会话 0-RTT 开流、SS2022 客户端缓冲复用和 TUN 栈读写零分配优化（`sequence: 1794300002`）。

## 验证与权利
本次在 Hytron 完成 `Kat-Server` 全包单元测试与 `go vet`，以及 Linux amd64 静态二进制构建与 CLI 版本核验。自研代码保留所有权利，第三方组件继续遵循各自原许可（详见 `THIRD_PARTY_NOTICES.md` 与 `kat-0.8.1-third-party-licenses.txt`）。
