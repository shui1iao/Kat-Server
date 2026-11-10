# Kat-Server v0.8.1

本版变更、默认值变化及测试边界以[发布说明](RELEASE_NOTES.md)为准。以下功能文档继承原服务端；命令及模块路径不改。

# Kat

Kat 是用 Go 编写的 Linux 纯正式入站+直连转发服务端代理内核，提供有界资源管理与 TCP/UDP 直连转发。当前版本 **0.8.1**，在 0.7.0 基础上修复 AnyTLS 旧会话授权撤销与 API/统计/选择状态热重载原子性，并增加 AnyTLS 入站自定义 padding 方案；既有功能、默认值和正式协议范围不变。命令名为 `kat`，模块名为 `github.com/shui1iao/Kat`。本项目不提供图形客户端、TUN 或公网管理接口；本机管理接口只监听 Unix socket 或回环地址。升级变化及限制见 [发布说明](RELEASE_NOTES.md)。

## 入站协议范围

本版本正式说明的入站协议限于以下五类，不表示对所有客户端、扩展和网络环境全面兼容：

| 协议 | TCP | UDP 与边界 |
| --- | --- | --- |
| SOCKS5 | CONNECT；用户名/密码认证；仅回环地址允许无认证 | UDP ASSOCIATE、可选 BIND、有界 UDP 分片重组；不支持 GSSAPI |
| AnyTLS | v2，兼容 v1；始终使用真实 TLS（省略 `tls` 时使用每次启动随机生成的自签证书，见下文）；逻辑多流与会话复用 | UoT v2 的连接及非连接模式，不是原生 UDP，不支持 UoT v1；FIN 关闭整个逻辑流，不承诺 TCP 半关闭 |
| Shadowsocks 2017 | 单身份 AEAD | 原生 UDP；支持下列三种方法，不支持旧式流密码 |
| Shadowsocks 2022 | 单身份 SIP022 | 原生 UDP；支持下列三种方法，不支持 EIH/iPSK 链或自动多用户密钥探测 |
| Trojan | 原版密码认证，TLS 1.2/1.3 | UDP-over-TLS；可配置 TLS 握手后的 TCP fallback（不是完整反探测系统） |

Shadowsocks 方法及凭据：

- SS2017：`aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`，使用 `ss.password`，不填 `ss.key`。兼容性密码派生不是抗穷举密码加固机制，应使用高熵密码。
- SS2022：`2022-blake3-aes-128-gcm` 使用 16 字节密钥；`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305` 使用 32 字节密钥。将密码学安全随机字节编码为标准 Base64 填入 `ss.key`，不填 `ss.password`。
- SS 的 TCP 与原生 UDP 监听同一 IP 和端口；原生 UDP 按 `listen` 中的 IP 选择地址族（`0.0.0.0` 与 IPv4 用 IPv4，显式 IPv6 只用 IPv6）。SS2022 初始盐及固定头要求在一次底层读取中收到，**不保证任意首段 TCP 分片均可接受**；后续记录支持分片。


## 构建与使用

使用 Go **1.26.9**。在仓库根目录构建 Linux amd64 静态二进制：

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -o kat ./cmd/kat
./kat version
./kat check examples/socks5.json
./kat run examples/socks5.json
```

`version` 输出 `kat 0.7.1`。`check` 严格检查 JSON、未知字段、凭据组合、限额及 TLS 证书/私钥配对（AnyTLS 入站省略 `tls` 时，`check` 同样会在内存中生成一张随机证书，与之后 `run` 使用的不是同一张），但不建立监听、不联网。`run` 启动服务；收到 SIGINT/SIGTERM 后停止接入，在 `drain_timeout` 内等待，超时取消并回收。

0.7.0 起另有管理子命令，用于查看和操作正在运行的实例，详见下文“日志、流量统计与管理接口”：

```sh
kat stats [--json]                 # 流量统计
kat stats reset                    # 累计统计清零
kat conns [--json]                 # 活跃连接明细（需在配置中开启）
kat conns close ID | --all         # 断开指定连接或全部连接
kat log level [debug|info|warn|error]  # 查看或切换日志级别
```

这些子命令都可以加 `-c 配置文件` 或 `--socket 路径` 指定实例。

首次构建需要准备 `go.mod`/`go.sum` 指定的依赖；依赖齐全后可以使用 `GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly` 离线构建。源码未内置全部依赖缓存。

[v0.7.1 Release](https://github.com/shui1iao/Kat/releases/tag/v0.7.1) 提供 [kat-0.7.1-linux-amd64](https://github.com/shui1iao/Kat/releases/download/v0.7.1/kat-0.7.1-linux-amd64)、对应 [.sha256](https://github.com/shui1iao/Kat/releases/download/v0.7.1/kat-0.7.1-linux-amd64.sha256) 及 [kat-0.7.1-third-party-licenses.txt](https://github.com/shui1iao/Kat/releases/download/v0.7.1/kat-0.7.1-third-party-licenses.txt) 许可附件。可先校验，再改为便于调用的名称：

```sh
sha256sum -c kat-0.7.1-linux-amd64.sha256
chmod +x kat-0.7.1-linux-amd64
./kat-0.7.1-linux-amd64 version
```

## 配置与示例

`examples/` 提供以下配置。所有示例只监听回环地址，并把 UDP 出站源地址绑定到回环地址，**仅用于本地目标，不能直接当作公网部署配置**。示例密码和 SS2022 的递增字节密钥都是公开测试值，必须替换，不能用于真实服务。

- 入站：`socks5.json`、`shadowsocks-2017.json`、`shadowsocks-2022.json`、`trojan-tls.json`、`anytls-tls.json`。
- `runtime.json`：日志、访问日志、统计、连接明细、管理接口（含回环 TCP 监听与密钥）和 `security` 写法。

0.7.0 起 Kat 默认拒绝被代理的流量访问本机回环地址（见下文“安全默认值”）。上面这些示例本来就只用于本机目标，因此入站示例和 `routing.json` 都写了 `"security": {"allow_loopback": true}`；部署到公网时请删掉这一项。

通用字段：

- `inbounds`：1–64 个入口；`protocol` 为协议标识，`listen` 为字面 IP 加端口，IPv6 使用 `[::1]:端口`。
- SOCKS5 的 `users` 使用 `username`/`password`；非回环监听必须配置用户，配置后不回退为无认证。SOCKS5 本身不加密，也不支持 TLS 包装，不应作为未加密的公网服务。
- Trojan 的 `users` 只使用 `password`，并且必须配置 `tls`。
- AnyTLS 使用 `anytls.password`，不填 `users`。`tls` 可以省略：省略时 Kat 使用每次启动随机生成的自签证书（ECDSA P-256，名称为 `localhost`，只在内存中，不写盘），**客户端必须跳过证书校验**；证书每次重启都会变，无法固定指纹，也无法用 CA 校验，因此不能防范中间人。写了 `tls` 时需要成对的 `cert`/`key` 或有效 `acme` 配置；`tls` 写成 `null`、`{}` 或不完整文件配对会被拒绝。`max_sessions`、`max_streams`、`session_streams`、`stream_bytes`、`session_bytes`、`slow_timeout` 限制会话、逻辑流、缓冲和慢消费者，默认值见下文“AnyTLS 身份额度”。同密码的入口共享身份、预算及有效 padding 方案，冲突配置会被拒绝。
- Shadowsocks 使用 `ss.method` 及相应凭据，不填 `users` 或 `tls`。`ss.tcp_salts`、`ss.salts_2017`、`ss.sessions` 控制有界保护状态；填 0 表示默认，不是禁用校验。相同方法和实际密钥的入口共享身份、重放保护及 UDP 关联，保护设置必须一致。
- `tls.cert`、`tls.key` 指向自行准备的证书和私钥，路径相对启动时的工作目录。Trojan/AnyTLS 入站示例需要先准备 `server.crt` 和 `server.key`（`anytls-tls.json` 演示的是自备证书写法）；`routing.json` 的 Trojan/AnyTLS 出站用同一份 `server.crt` 作为 `tls.ca`，证书需包含 `localhost`。仓库不附生产证书或私钥。
- `udp_bind_ipv4`、`udp_bind_ipv6` 可指定直连（direct）UDP 出站的本机源地址；省略时由系统路由选择。它们不是访问控制系统（目标地址限制见 `security`）。

`limits` 的常用字段如下；计数或时长填 0/省略一般表示默认，`tcp_idle` 的 0 表示正式支持协议不启用该闲置超时。时长使用 `"5s"`、`"5m"` 等字符串。

| 字段 | 默认值 | 作用 |
| --- | --- | --- |
| `connections` / `logical_streams` | 4096 / `max(8192, 各 AnyTLS 身份 max_streams 之和)` | 物理连接与逻辑流额度 |
| `handshakes` / `dials` | 512 / 512 | 并发握手及拨号额度 |
| `udp_associations` | 1024 | UDP 关联额度 |
| `udp_queue` / `udp_queue_bytes` | 16 / `udp_queue × 65507` | 每关联队列的包数与载荷字节预算 |
| `udp_targets` | 256 | 每关联有效回包目标数 |
| `buffer_size` / `pool_buffers` | 16384 / 128 | 普通复制缓冲大小与池缓存数量 |
| `handshake_timeout` / `dial_timeout` | 10s / 5s | 握手与拨号超时；经代理出站时两者之和是拨号（含整条链路握手）的总预算 |
| `drain_timeout` / `udp_idle` | 5s / 60s | 退出等待与 UDP 闲置超时；`udp_idle` 也用于代理 UDP 会话的空闲回收 |
| `tcp_idle` | 0 | TCP 活动闲置超时，默认关闭 |
| `disable_fast_path` | false | 强制使用普通缓冲复制路径 |

计数类字段的取值范围与 0.6.1 相同（`connections`、`logical_streams`、`handshakes`、`dials`、`udp_associations`、`pool_buffers` 为 1–65536，`udp_targets` 为 1–1024），显式填写的值按原规则校验和生效，只有省略的字段才取上表的默认值。

`logical_streams` 的自动取值：所有不同密码 AnyTLS 身份的 `max_streams` 之和必须不超过 `logical_streams`。省略（或填 0）时自动取 `max(8192, 该和)`，同一密码出现在多个入口只计一次，因此多个 AnyTLS 身份都用默认额度也能通过检查（例如 3 个默认身份得到 12288）；该和超过 65536 时仍会被拒绝，需要为各身份显式填写较小的 `max_streams`。显式填写 `logical_streams` 时不做任何自动调整，超出即被 `kat check` 拒绝。

0.7.1 起，AnyTLS 入站可在 `anytls` 对象内设置 `padding_scheme` 字符串，直接填写方案文本，例如：

```json
"anytls": {"password": "your-password", "padding_scheme": "stop=2\n0=30-30\n1=100-200"}
```

省略或空字符串使用内置默认方案；显式填写同一份默认文本与省略等价，不会因此更换 codec。同密码的所有入站必须使用相同的有效方案及预算。方案按底层 AnyTLS 语法校验，最多 4096 字节（不是字符数）；`kat check`、启动和重载都拒绝非法或超限文本，失败重载不改变当前运行状态或消耗成功 generation。没有文件入口。

方案用于协议协商/下发：客户端 settings 中的方案 MD5 与服务端不同时，服务端通过 `cmdPadding` 原样下发文本；匹配则不下发。Kat 不会据此把服务端所有发送流量改写成该填充形态，客户端如何使用方案由其实现决定。重载方案只影响新绑定接入的 TLS carrier；旧 carrier（包括随后新开的逻辑流）继续使用旧 codec/方案，不热广播、不强断。单纯修改 padding 不撤销会话授权，旧 carrier 新开的流仍按当前路由代处理，已建立 TCP/UDP 流继续。客户端会话池可能继续复用旧 carrier，因此不能承诺重载后客户端立即全部采用新方案，也不承诺反封锁效果。

AnyTLS 身份额度（写在 `anytls` 对象内，同密码的入口共享）：

| 字段 | 默认值 | 作用 |
| --- | --- | --- |
| `max_sessions` | 跟随 `limits.connections`（默认 4096）；显式填写时取值 1–65536 | 同一密码的物理会话（TLS 连接）总数。Surge、mihomo、sing-box 等客户端在没有空闲会话时会为每个并发请求新开会话；mihomo 还让每条 UDP 流独占一个会话，并在最后一个包之后再保留 60 秒。因此它大致等于该密码下所有用户的“并发 TCP 连接数 + 最近 60 秒内活跃的 UDP 流数”。省略或填 0 时等于 `connections`，调小 `connections` 会一起变小；每个会话都占一个物理连接，同样受 `connections` 限制 |
| `max_streams` | 4096（上限 65536） | 同一密码跨所有会话的逻辑流总数 |
| `session_streams` | 64（上限 64） | 单个会话内的并发逻辑流 |
| `stream_bytes` / `session_bytes` | 131072 / 1048576 | 单流 / 单会话的缓冲预算，入、出方向分别计费 |
| `slow_timeout` | 60s（取值 1ms–60s） | 慢消费者及写入超时：缓冲满后等待对端读取的最长时间，超时关闭整个会话 |

默认额度按几位用户用 Surge、mihomo、sing-box 日常浏览、看视频、玩游戏的负载设定；超过额度时直接拒绝，不会无限占用内存。

**内存说明。** 正常使用时 Kat 的内存占用不大：在本机回环上用 sing-box 或 mihomo 作客户端、几百个并发流（AnyTLS、Shadowsocks 2022、Trojan，含 UDP）测试，进程 RSS 峰值约 35–105 MiB；500 个 AnyTLS 会话各下载 4 MiB、客户端先暂停读取 6 秒的压力场景约 105–116 MiB。但默认值下字节型缓冲的理论上界较大：持有凭据的使用者如果刻意把所有队列都占满，单个 AnyTLS 身份时约 2.9 GiB（主要是 AnyTLS 会话缓冲 `min(max_sessions × 2 × session_bytes, max_streams × 2 × stream_bytes)` 约 1 GiB，`max_sessions` 默认跟随 `connections` 后由后一项决定；加上 UDP 关联队列 `udp_associations × udp_queue_bytes` 约 1 GiB；会话数上限变大后，每个会话不计入上式的固定开销合计最多约 0.1 GiB），每多一个使用默认额度的 AnyTLS 身份再增加约 1 GiB。2 GB 等内存较小的机器，或需要隔离不可信用户时，请在配置中显式填写更小的值，例如 `limits.udp_associations: 256`，以及 AnyTLS 的 `max_sessions: 128`、`max_streams: 1024`，这两项缓冲各降到约 256 MiB；也可以减小 `connections`（未填写的 `max_sessions` 随之变小）、`session_bytes`、`stream_bytes`。`slow_timeout` 不改变这些上界，只决定对端不读时缓冲最多被占用多久。

这些额度不是整个进程的内存硬上限；TLS、协议保护状态、Go 栈和内核 socket 等还有额外开销。队列满可能丢弃 UDP 包。回包仅允许来自关联实际请求过且未过期的精确 IP:port，不承诺任意 full-cone。SOCKS5 UDP 不接受跨 IP 重绑定；同 IP 的不可信进程可能在未限定源端口时抢占首个 UDP 包，部署者需要限制访问。

SS 原生 UDP 的闲置按“最后一次合法活动之后”计时：通过认证的客户端包，以及来自已授权且未过期目标的合法回包，都会续期；未知或过期来源不续期。

### SS2017 可选接收缓冲

仅 Linux 的 SS2017 入口可选择 `ss.udp_rcvbuf_2017: 1048576`。**默认省略或 0，不改 socket 接收缓冲，也不占该额外预算**；其他非零值及 SS2022 使用此项都会被拒绝。

启用时按内核读回的接收缓冲值检查至少 1 MiB；原默认值已更大时不缩小。相对原值的正增量计入**全进程额外 8 MiB socket 接收额度上限**，不是进程总内存上限。额度不足、平台不支持或内核实际授予不足时明确失败，不静默降级，也不自动修改系统参数。较大缓冲可能减少短时突发丢包，但积压时会增加排队延时；应按实际业务选择，不是无条件推荐设置。

### SS2022 会话与来源迁移

0.5.19 复用 UDP 会话密码对象；0.5.20 将 UDP 解密和回包处理移出共享状态锁，并增加有界读取并发，不改变认证、重放窗口或目标回包限制。

同身份多个监听入口共享 UDP 会话。来源迁移必须先通过认证与重放校验；回包目的始终使用最新认证来源。迁移期间可能短暂从旧监听入口发出回包，**不承诺回包源监听入口立即切换**。需要固定源端口的客户端或网络策略应考虑这一边界。

## 基础 DNS 与直连解析

服务端仅提供直连转发（`direct`），不支持 `outbounds`、`groups`、`providers`、`routing`、`rule_sets`、`geoip`、`geosite`、`asn` 及入站 `sniff`（配置中出现这些字段会严格拒绝报错）。

### DNS

`dns` 块决定直连出口如何解析域名：

- 省略 `dns`、空 `{}` 或仅设置缓存均使用默认链：依次尝试 UDP `8.8.8.8:53`、UDP `1.1.1.1:53`，全部瞬时失败后才使用系统 DNS。`servers` 是 **1–16 项有序字符串数组**，例如 `"servers":["udp://1.1.1.1:53","https://dns.google/dns-query"]`；不排序、不去重。兼容原单值 `server`（一个上游后接系统兜底），但不能和 `servers` 同时出现。显式 `server: "system"` 只用系统解析，不加应用层缓存。
- 上游格式为 IP 或主机名（可带端口，默认 UDP 53）、`udp://主机[:端口]`、`tcp://主机[:端口]`，或 `https://主机[:端口]/路径`（DoH，POST，标准证书与 SNI 校验）。上游域名由系统解析器引导，不递归查询自身。
- `cache_entries`：0–4096；自定义及默认链默认 256，0 关闭；显式 `system` 只能省略或填 0。完整说明见 [DNS 文档](docs/dns-routing.md)。

## TLS、ACME 与 TCP Fast Open

Trojan/AnyTLS 入站支持证书文件跟随、reload 换证、ALPN、TLS 1.2/1.3 版本范围、TLS 1.2 套件及 SNI 多证书；新证书只影响新握手，已有 TLS 连接不中断。ACME 支持 Cloudflare DNS-01、HTTP-01 standalone、HTTP-01 webroot、TLS-ALPN-01，持久保存账户/证书并自动续期。入站与 direct 出站可选 TCP Fast Open，**默认关闭，不修改宿主 sysctl**；实际生效需要平台、内核与对应系统位支持。证书文件跟随默认关闭；ACME 只有显式配置才启用，默认目录为 Let's Encrypt 正式环境，试用请显式选择 staging。完整字段、权限和公网挑战端口条件见 [TLS/ACME/TFO 文档](docs/tls-acme-tfo.md)。不支持 mTLS、ECH、OCSP stapling。

## 日志、流量统计与管理接口（0.7.0）

以下 `log`、`stats`、`api`、`security` 四个配置块都是可选的。**不写 `log` 时，日志输出与 0.6.3 相同**：stderr（systemd 下即 journald）、纯文本、`info` 级别，原有事件的内容、5 秒抑制和隐私取舍都不变；启动时还会输出一行 `kat event=api_ready unix=…`（管理接口已就绪）。完整写法见 `examples/runtime.json`。

### 日志 `log`

| 字段 | 默认值 | 作用 |
| --- | --- | --- |
| `level` | `info` | `debug` / `info` / `warn` / `error`。诊断类 `event=failure` 与各种 `*_failed` 为 `warn`；启动、监听、策略组切换、规则集加载等为 `info`；管理请求（`api_request`）、统计落盘（`stats_saved`）为 `debug` |
| `format` | `text` | `text` 或 `json`。`json` 时每行一个对象：`time`、`level`、`event` 及该事件的其余字段；不是 `kat event=` 形式的行放在 `msg` 字段 |
| `file` | 空（stderr） | 绝对路径时写入该文件（文件权限 0600，目录不存在时按 0750 创建），文本格式每行前加 RFC 3339 时间 |
| `max_size_mb` / `max_backups` | 10 / 3 | 写文件时按大小轮转：即将超过 `max_size_mb`（1–1024）时，`kat.log` → `kat.log.1` → … → `kat.log.N`，最多保留 `max_backups`（1–100）个旧文件 |
| `access` | `false` | 访问日志，见下文 |

运行中可以用 `kat log level debug` 等命令切换级别，立即生效，并输出 `kat event=log_level_changed from=… to=…`；**切换只在本次运行内有效，重启后回到配置文件中的级别**。配置热重载时，只有配置文件里的 `log.level` 本身改变了才会覆盖运行中切换的级别，否则保持当前级别。

**访问日志**（`log.access: true`）在每条连接结束时写一行（UDP 为每个关联一行），级别为 `info`、不做抑制，与诊断日志写到同一个输出：

```text
kat event=access id=12 network=tcp inbound=shadowsocks/0.0.0.0:8388 src=203.0.113.0/24 dst=www.example.com:443 rule=domain_suffix:example.com->pick chain=pick>auto>node-a result=ok up=812 down=40213 duration_ms=5230
```

- `src` 是客户端来源地址的截断前缀：IPv4 保留 /24，IPv6 保留 /48，不记录完整来源地址；`dst` 是客户端请求的完整目标（域名或 IP 加端口）。
- `rule` 是命中的规则（见下文“名称”），`chain` 是经过的策略组和最终出站，`result` 为 `ok`、`blocked`（被 `security` 拒绝）、`rejected`（规则拒绝）、`dns_failed`、`dial_failed`、`closed_by_api`（被 `kat conns close` 断开）等。
- `up`/`down` 是这条连接的有效载荷字节数（口径见下文）。UDP 关联的 `dst` 是该关联的第一个目标，`rule`/`chain` 是最近一次路由的结果。
- 访问日志会记录目标地址，请按需开启并自行管理日志文件的保存和权限。日志级别设为 `warn` 或 `error` 时访问日志也不输出。

### 流量统计 `stats`

流量统计始终在内存中计数，`kat stats` 可随时查看：

- **全局**：累计上行/下行字节。
- **每入站**：名称为 `协议/监听地址`，例如 `shadowsocks/0.0.0.0:8388`。
- **每出站与每策略组**：名称即配置中的 `name`；内置 `direct`、`reject` 也列出。一条连接经过的策略组及最终选中的出站都会计入（例如 `pick>auto>node-a` 同时计入 `pick`、`auto`、`node-a`）；`via` 链式代理底层用来连接上游服务器的出站不重复计入。
- **每条规则**：命中次数和流量。名称为 `条件:值->去向`，例如 `domain_suffix:example.com->pick`、`network:udp->direct`、`rule_set:block-list->reject`；未命中任何规则时记为 `final->去向`；带 `no_resolve` 的 IP 类规则写作 `ip_cidr:…,no_resolve->去向`；完全相同的规则再次出现时加 `#2`、`#3`。TCP 每条连接计一次命中，UDP 每个关联对每个不同目标计一次命中。命中后被拒绝或拨号失败的连接也计入命中次数，但没有流量。
- **当前连接数**：正在转发的 TCP 连接数、UDP 关联数，以及已接入的入站传输连接数（例如一个 AnyTLS 会话算一个，即使其中有多个逻辑流）；另有本次启动以来因额度被拒绝的入站连接数。
- **实时速率**：最近约 5 秒的平均上行/下行速率（每秒采样一次）。

**字节口径：** 只计代理转发的有效载荷，即客户端应用与目标之间实际传输的内容字节；不含 TLS、Shadowsocks、Trojan、AnyTLS、SOCKS5 等协议的封装、握手、认证和填充开销，也不含 TCP/IP 头。“上行”为客户端到目标，“下行”为目标到客户端。UDP 计每个数据报的载荷。因此统计值通常小于网卡或服务商计量的流量。

| 字段 | 默认值 | 作用 |
| --- | --- | --- |
| `file` | 见“默认路径” | 累计值的持久化文件（绝对路径） |
| `persist` | `true` | 是否把累计值写入 `file`、启动时读回；`false` 时只在内存中计数，重启清零 |
| `save_interval` | `60s` | 落盘间隔，5s–24h |
| `connections` | `false` | 活跃连接明细，见下文 |

**持久化：** 累计值（全局、每入站、每出站、每组、每条规则）每隔 `save_interval` 写入一次，正常退出（SIGINT/SIGTERM）时再写一次；写入方式是同目录临时文件加原子改名，不会留下半个文件。启动时读回，因此**重启不会清零**；被强制杀死时最多丢失最近一个间隔的增量。

- 持久化文件按名称保存各项计数，与配置中的顺序无关；重启后配置里已经不存在的入站、出站、组或规则，其旧计数会被丢弃。配置热重载不清零：总量、入站、出站、组按名称延续，规则按规则本身（上面的规则名称）延续。
- 只做累计值，不按天保存历史。
- 写入失败只告警（`kat event=stats_save_failed`，并计入 `kat stats` 的 `save_errors`），不影响转发。
- 文件损坏或无法解析时告警（`kat event=stats_load_failed reason=corrupt`），把坏文件改名为 `原名.corrupt-时间` 保留，然后从零开始计数，不会退出。
- 同一个统计文件同时只能被一个进程使用（旁边的 `.lock` 文件加锁）。另一个实例用到同一个文件时，它会告警（`stats_persist_disabled reason=file_in_use`）并只在内存中计数。
- `kat stats reset` 把所有累计值清零、重新记录起始时间并立即落盘；当前连接的明细计数不受影响。

**活跃连接明细**（`stats.connections: true`）：在内存中登记每条正在转发的 TCP 连接和每个 UDP 关联，**不落盘**，连接结束即移除。`kat conns` 列出 ID、网络类型、入站、来源（同样截断为 IPv4 /24、IPv6 /48）、完整目标、命中规则、出站链、开始时间、时长和上下行字节；`kat conns close ID` 断开指定连接，`kat conns close --all` 断开全部。未开启时这些命令会明确提示“connection details are disabled”。开启明细会给每条连接增加少量内存和登记开销。

### 管理接口 `api` 与命令行

Kat 自有的 HTTP/JSON 接口（不兼容 Clash API，也不提供 Prometheus 指标），路径带版本前缀 `/v1`：`GET /v1/version`、`GET /v1/stats`、`POST /v1/stats/reset`、`GET /v1/connections`、`DELETE /v1/connections`、`DELETE /v1/connections/{id}`、`GET /v1/log/level`、`PUT /v1/log/level`（请求体 `{"level":"debug"}`）；支持 `POST /v1/reload`、`GET /v1/security/bans`、`DELETE /v1/security/bans`。命令行子命令都通过它工作。

| 字段 | 默认值 | 作用 |
| --- | --- | --- |
| `enabled` | `true` | 是否启用管理接口 |
| `socket` | 见“默认路径” | Unix socket 路径（绝对路径） |
| `listen` | 空 | 可选的额外 TCP 监听，**只允许字面回环地址**（`127.0.0.0/8` 或 `[::1]`）加端口；写 `0.0.0.0`、公网地址、主机名等都会被 `kat check` 拒绝 |
| `secret` | 空 | 配置 `listen` 时必填，至少 16 字节；请求须带 `Authorization: Bearer <secret>`，比较为常量时间。未配置 `listen` 时不能填写 |

- Unix socket 文件权限为 0600，属主为运行 Kat 的用户；Kat 创建的目录权限为 0700。Linux 上还会检查对端进程的用户，只接受 root 和运行 Kat 的同一用户，其他用户即使能打开 socket 也会被拒绝。
- socket 路径已有一个活着的 Kat 实例时，新实例不会抢占，而是告警 `kat event=api_unavailable` 并在没有管理接口的情况下继续运行；路径上是普通文件时也不会删除它。管理接口不可用不影响转发。
- 命令行只使用 Unix socket。TCP 监听供本机其他程序（例如 `curl -H "Authorization: Bearer …" http://127.0.0.1:端口/v1/stats`）使用。

**找到要管理的实例：**

- `kat stats -c /etc/kat/ss.json`：按配置文件找实例。配置里写了 `api.socket` 就用它，否则用该配置的默认 socket 路径。
- `kat stats --socket /run/kat/ss.sock`：直接指定 socket。
- 两者都不写时，在默认目录里查找：只有一个实例时直接使用；有多个实例时报错并列出它们，请用 `-c` 或 `--socket` 指定。

### 默认路径

默认路径按**配置文件名（去掉扩展名）**区分实例，同一台机器上的多个 Kat 进程互不冲突。实例名中 `A–Z a–z 0–9 . _ -` 以外的字符换成 `_`，最长 64 字节。

| 平台与用户 | 管理 socket | 统计文件 |
| --- | --- | --- |
| Linux，root（例如 systemd 系统服务） | `/run/kat/<实例名>.sock` | `/var/lib/kat/<实例名>.stats.json` |
| Linux，普通用户 | `$XDG_RUNTIME_DIR/kat/<实例名>.sock`（未设置时 `/tmp/kat-<uid>/`） | `$XDG_STATE_HOME/kat/<实例名>.stats.json`（未设置时 `~/.local/state/kat/`） |
| Windows | `%ProgramData%\Kat\<实例名>.sock` | `%ProgramData%\Kat\<实例名>.stats.json` |

例如 `kat run /etc/kat/ss.json` 与 `kat run /etc/kat/anytls.json` 分别使用 `/run/kat/ss.sock`、`/var/lib/kat/ss.stats.json` 和 `/run/kat/anytls.sock`、`/var/lib/kat/anytls.stats.json`。目录不存在时自动创建（权限 0700）。

- 不同目录下的同名配置文件（例如两个 `config.json`）会得到相同的默认路径，后启动的实例会告警并失去管理接口和持久化；这种情况请改用不同文件名，或显式填写 `api.socket` 和 `stats.file`。
- systemd 单元如果启用了 `ProtectSystem=strict`、`ReadOnlyPaths` 等沙箱设置，需要让 `/run/kat` 和 `/var/lib/kat` 可写（例如 `RuntimeDirectory=kat`、`StateDirectory=kat`，并设置 `RuntimeDirectoryPreserve=yes` 或为每个实例使用独立子目录，避免一个实例停止时删除共享目录），或者在配置中指定可写路径。未设置这些沙箱选项的 root 服务无需改动。路径不可写时只告警，转发不受影响。
- Windows 上 Go 支持 AF_UNIX，但 socket 的访问控制依赖所在目录的权限，Kat 不额外检查对端用户；请确保该目录只有管理员和运行 Kat 的用户可以访问。Windows 版本只做过交叉编译。

### 安全默认值 `security`

**0.7.0 起，被代理的客户端流量默认不能访问本机：** 直连（`direct`）最终拨号的目标地址如果是回环地址（`127.0.0.0/8`、`::1`）、未指定地址（`0.0.0.0/8`、`::`，它们会落到本机）或它们的 IPv4 映射形式（如 `::ffff:127.0.0.1`），连接会被拒绝；TCP 与 UDP 都适用，域名解析后落到这些地址也一样（例如 `localhost`）。这同时保护了只监听回环地址的服务，包括 Kat 自己的管理 TCP 端口。被拒绝的 TCP 连接在访问日志中为 `result=blocked`，诊断日志为 `stage=dial reason=destination_not_allowed`；被拒绝的 UDP 数据报直接丢弃。

| 字段 | 默认值 | 作用 |
| --- | --- | --- |
| `allow_loopback` | `false` | `true` 时允许访问上述本机地址（0.6.3 的行为） |
| `block_private` | `false` | `true` 时还拒绝私有与链路本地地址：`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`100.64.0.0/10`、`169.254.0.0/16`、`fc00::/7`、`fe80::/10` |

- 只作用于客户端流量经 `direct` 的最终拨号（包括策略组里的 `direct` 成员）。Kat 自己发起的连接不受影响：DNS 查询、策略组测速、规则集与 GeoIP 下载，以及连接上游代理服务器（即使上游就在本机回环地址上）。经上游代理转发的目标由上游决定，Kat 不检查。
- `allow_loopback: true` 时，回环地址上的服务（包括管理 TCP 端口）都可被客户端访问，管理 TCP 端口仍需要 `secret`。

```json
"security": {"allow_loopback": false, "block_private": true}
```

## 入站安全与 SOCKS5 扩展

### 来源限制与临时封禁

```json
"security": {
  "auth_ban": {"enabled": true, "threshold": 30, "window": "1m", "duration": "10m"},
  "max_connections_per_ip": 100
}
```

- 两项默认关闭。启用封禁而省略参数时：固定 1 分钟窗口内失败 30 次，封禁 10 分钟；IPv4 按地址、IPv6 按 /64（并发上限相同）。并发上限计实际 TCP 连接，AnyTLS 会话不等同于逻辑流，UDP 关联不算 TCP 并发。
- 认证失败：SS 首块解密失败、AnyTLS 密码哈希不符或 padding 超限、Trojan 的 56 位十六进制哈希不匹配、SOCKS5 用户名或密码错误。SS2017 无法区分错密码、错方法和随机探测；Trojan 非十六进制探测不计猜密。UDP 错误认证不计数，避免伪造源地址造成误封。
- 封禁对所有新 TCP 连接和 SS 新 UDP 关联生效，不切断已有连接。每入站 `sources` 可写 `{"allow":["192.0.2.0/24"],"deny":["192.0.2.9"]}`，接受 IP/CIDR；黑名单优先，白名单非空时只接受其内来源。名单同样限制 SS 新 UDP 关联。
- 重载后新连接应用新名单/上限，已有连接保留；连接计数一直进行。封禁表跨重载保留，关闭封禁时清空（旧代迟到的认证失败也不能重新封禁），重启清空。
- `kat bans [--json]` 查看，`kat bans remove SOURCE` 解封；IPv6 可传地址或 /64。API 为 `GET /v1/bans`、`DELETE /v1/bans/{source}`，权限同管理接口。CLI 显示完整来源，诊断日志只显示 IPv4 /24、IPv6 /48。
- 失败来源/封禁表各最多 65536 条，满后不再新增并增加 `security.untracked_failures`；每秒清扫过期项。统计的 `security` 包含封禁/失败/来源数、三类安全拒绝及分片缓存字节。安全拒绝发生在握手额度前，**不计入** `connections.rejected_since_start`；后者只统计通用额度拒绝。
- 私网默认放行，回环/未指定地址默认拒绝，管理回环接口因此受到保护；`allow_loopback`/`block_private` 的意义不变。

### Trojan fallback

Trojan 入站可写 `"fallback":"127.0.0.1:8080"`（示例，须替换为自备网站），只接受字面 IP:端口。TLS 握手成功后非 Trojan 请求原样回落，包括已读字节；回落允许由 Kat 连接本机回环网站，不受客户端回环目标限制。拨号计入 dials，转发受 tcp_idle 限制；不可达时发送 TLS close_notify 并关闭。握手失败或一直不发送应用数据不会回落。

**时序变化：无论是否配置 fallback，读到第一个非法 Trojan 字节就立即判失败，不再等满 56 字节。** fallback 不保证对所有探测行为与普通网站完全相同。

### SOCKS5 BIND 与 UDP 分片

BIND 默认关闭（回复 07）。在 SOCKS5 入站写 `"socks5":{"bind":{"listen":"127.0.0.1","ports":"40000-40031","timeout":"30s"}}` 开启。listen 默认为入站 IP；端口范围最多 4096 个，不能覆盖配置内入站或管理监听。先回复监听地址，再回复连接对端地址，随后双向转发；只按请求目标 **IP** 匹配（零地址接受任意 IP，不用 DST.PORT 过滤），错误对端拒绝后继续等待。等待占一个 dials 槽位；超时回复 01，目标被安全策略禁止回复 02，关闭控制连接会释放监听。BIND 不经过路由规则，直接转发并统计 tcp/direct。

UDP 分片重组默认开启：每关联缓存载荷最多 65535 字节，全局默认 4MiB，超时默认 5s。单入站可写 `"socks5":{"udp_fragment":{"disabled":false,"max_bytes":65535,"timeout":"5s"}}`；全局为 `limits.udp_fragment_bytes`（65535–268435456）。单关联上限 1024–65535，超时 5–60s。超预算丢弃并释放当前队列，超时或关闭关联也释放。仅向目标发送完整报文，回包不分片。

**排序差异：实现允许乱序，未采用 RFC 1928 中较小 FRAG 重置队列的要求。** 相同内容的重复片忽略，内容冲突、换目标或结束位置冲突会开启新报文，FRAG=0x80 畸形丢弃。BIND 和分片没有主流客户端覆盖证据，只使用独立的 RFC 1928 格式客户端验收，不能据此宣称严格 RFC 全兼容。

## 配置热重载（0.7.0）

### 触发方式

- **SIGHUP**：`kill -HUP <进程号>`。systemd 单元可以加 `ExecReload=/bin/kill -HUP $MAINPID`，之后用 `systemctl reload 单元名` 触发。
- **`kat reload`**：通过管理接口（`POST /v1/reload`）触发，查找实例的方式与 `kat stats` 相同（`-c 配置文件` 或 `--socket 路径`）。只接受 Unix socket 调用，或带 `secret` 的回环 TCP 调用。Windows 没有 SIGHUP，只能用这种方式。
- 两种方式都重新读取**进程启动时的那个配置文件**，默认路径的推导也和启动时一样。Kat 不监视配置文件，文件改动后不会自动重载。
- **行为变化：** 0.6.x 没有处理 SIGHUP，收到后进程会被直接终止（不做正常退出的收尾）。0.7.0 起 SIGHUP 改为重载配置，进程继续运行。

成功时 `kat reload` 输出 `configuration reloaded (generation N, X ms)`，退出码为 0；日志记录 `kat event=reload_ok trigger=api|sighup generation=N inbounds=M duration_ms=X`。`generation` 是本次运行中已生效的配置代数，启动时为 1。

### 原子性与失败处理

重载分两步：先在不影响运行状态的情况下完整构建新配置（校验、DNS、出站、组、规则、规则集与 GeoIP 的本地文件、入站参数，以及新增地址的监听 socket），全部成功后才一次性切换。转发、日志、管理监听及统计/选择状态目标的准备阶段任何一步失败，整次重载作废，候选 socket 和锁全部释放，正在运行的配置、管理鉴权、统计路径/实例锁、累计值及运行选择保持原样；失败不消耗 generation。

失败时 `kat reload` 以非零退出码结束，并输出 `kat: reload failed (阶段): 原因; the running configuration is unchanged`；日志记录 `kat event=reload_failed trigger=… stage=… reason=…`。阶段有 `load`（读文件或 JSON 语法错误，带行号）、`validate`（校验不通过）、`dns`、`routing`、`inbound`、`bind_tcp` / `bind_udp`（新端口被占用等）、`log`（新日志文件打不开）。SIGHUP 触发的重载失败只记日志。

### 生效范围

- **已有连接不受影响**：已建立的 TCP 连接和 UDP 关联继续使用建立时的那一代配置（路由结果、出站、组），直到自然结束；即使它使用的出站在新配置里被删除也一样，不会因为重载被强制断开。旧的一代配置按引用计数管理，最后一条连接结束后释放（关闭其出站、组的后台测速、规则集刷新和 DNS）。
- **新连接用新配置**：重载完成后建立的连接按新配置路由。
- AnyTLS 会话（客户端会复用的长连接）中新开的逻辑流按当前配置路由并重新核对原监听的连续授权期。修改密码、删除入站、换监听或切换协议后，旧会话只拒绝新开的 TCP/UDP 流，已准入的流继续完成；之后恢复原配置不会让已撤销会话复活。无关规则、名称、预算和 padding 方案重载不撤销会话，新会话按新配置认证。

各部分的处理方式：

| 配置 | 重载后的行为 |
| --- | --- |
| 新增入站 | 立即开始监听 |
| 删除入站 | 关闭监听，不再接收新连接；已有连接自然结束。Shadowsocks 的 UDP socket 在其上最后一个 UDP 关联结束后关闭 |
| 地址和端口不变的入站 | 复用原来的监听 socket，不重新 bind，没有空窗；修改密码、方法、TLS、用户等参数只对新连接生效 |
| 修改入站端口 | 新端口开始监听，旧端口停止接收新连接，旧连接自然结束 |
| 出站、策略组、规则、规则集、GeoIP、DNS | 整体换成新配置。DNS 缓存清空；规则集和 GeoIP 从本地文件重新读入，配置了 `url` 的按新配置重新开始定时刷新；`url-test`、`fallback`、`smart` 组的测速和评分状态从头开始 |
| `limits` | 全局额度（`connections`、`handshakes`、`dials`、`udp_associations`、`logical_streams`）立即按新值生效；调低时不收回已占用的额度，只是新的申请要等用量降到新上限以下。其余额度和超时对新连接生效 |
| `log` | `level`（见上文）、`access` 立即生效；`file`、`format`、轮转参数改变时换用新的输出，新文件打不开则整次重载失败 |
| `security` | 对新连接立即生效 |
| `stats` | `connections` 只影响之后建立的连接；`save_interval` 立即生效；新实例锁与统计/选择状态文件预备成功后才切换 `file` / `persist`，累计值及运行选择延续，不从新目标读回累计值 |
| `api` | 新增监听先 bind、提交后才提供服务；不变地址复用监听并按每个请求更新 secret（含 keepalive）；撤下接口的在途请求安全完成，包括触发重载的请求 |

**运行期资源准备：** 新管理 socket / 端口无法监听、双监听只部分成功、新统计实例锁被占用，或统计/选择状态目标无法写入或原子替换时，整次重载失败（`stage=api` / `stage=stats`），转发与管理/统计均不切换。预备不覆盖已有目标文件或删除别人的 socket。启动仍保持管理/统计失败仅告警、转发可继续的既有行为；提交后周期落盘的后续磁盘故障仍告警。这是进程内重载事务，不保证断电恢复或预知未来磁盘/外部文件修改故障。

**授权提交边界：** 只有成功提交的重载才撤销受影响 AnyTLS 会话的新流准入；API/统计准备失败不会把仍生效的旧身份误撤销。撤销不强制关闭 carrier 或已经建立的流。

**统计延续：** 重载不清零，总量、入站、出站、组按名称延续，规则按规则本身延续（同一条规则即使在列表中的位置变了，计数也继续）。

## 验证与性能口径

0.7.1 的三项变更已完成全包普通单元测试与 `go vet`，以及 AnyTLS padding/会话撤销、运行期原子重载和交叉回归的重点 race。2026-10-27 在同一功能源码仅将 CLI 版本设为 0.7.1 后，又完成**全包 race**（`go test -race -p 2 -parallel 2 -count=1 -timeout=900s ./...`）及全包 `go vet`，均通过，无 DATA RACE；Linux/Windows amd64 均交叉构建成功，Linux 实际运行版本命令。Windows 未做实机运行测试，正式附件仍只提供 Linux amd64。

0.7.0 基线已有 sing-box 1.14.3、mihomo v1.19.33 的 SS2022、AnyTLS、Trojan、SOCKS5 TCP/UDP 实连，嗅探开关两轮共 16 组；UDP 经代理查询 `whoami.cloudflare` 核对真实出口。该旧基线另完成一次本机回环混合负载 **7200.220 秒**，随后在同一进程观察 **300.087 秒**：239 次负载内重载、160 次动态 provider 节点变更、旧流/新流各 320 次校验；正式负载客户端错误为空，goroutine 16→16、fd 15→15，HeapLive 采样峰值约 64.38 MB、恢复约 6.06 MB，无 OOM。外围观察器曾有一次归属检查误报，独立清场已核实；不将全部工具退出码宣称为零。**这些是 0.7.0 旧基线证据，不是 0.7.1 重做的 2 小时或完整客户端矩阵验收。**

0.7.1 发布准备从干净公开源码构建正式 Linux 附件，并做精确版本、静态 ELF/amd64 与 CLI 定向检查；不重跑完整客户端矩阵或长测。**未补 6 小时运行测试**，未重做 2 小时负载、真实 ACME 签发续期、TFO 抓包、超过 4096 并发压力、全部规则/组/外部订阅矩阵或公网长时间延迟场景。已有分项验证不冒充最终版本的全覆盖验收。

第三方客户端专项只覆盖上述客户端，不保证 Surge、其他发行版或公网高延迟场景；没有在 2 GB 内存机器上实测。内存预算估算不是进程硬限制。更早版本的测试和短时性能观察仅适用于各自代码与条件，本版不作性能领先、一般安全审计、普遍无泄漏、长期 SLO 或生产可用性承诺。

## 权利与第三方许可

**Kat 自研代码保留所有权利。** 公开可读不等于授予任意使用、修改或再分发许可；本仓库不设顶层自研 `LICENSE`。

第三方代码及其许可材料**仍各自遵循原许可**，不受上述自研权利声明替代或收回：

- Go 标准库与 `golang.org/x/crypto`、`golang.org/x/net`、`golang.org/x/sys` 适用 BSD-3-Clause（附 PATENTS）。
- `lukechampine.com/blake3` 与 `github.com/klauspost/cpuid/v2` 适用 MIT。
- 原始许可与专利文本保留于 `third_party/licenses/` 及 [第三方说明](THIRD_PARTY_NOTICES.md)；随二进制分发的 `kat-0.8.1-third-party-licenses.txt` 附件汇总全部适用第三方许可原文。
