# 基础 DNS 与直连解析

本文说明服务端 `dns` 配置块的语法、解析顺序、预算与缓存行为。服务端仅支持直连转发（direct），不再包含 `routing`、`outbounds`、`groups`、`providers`、`rule_sets`、`geoip`、`geosite`、`asn` 或入站 `sniff`。

## DNS
```json
{"dns":{"servers":["udp://8.8.8.8:53","udp://1.1.1.1:53"],"cache_entries":256}}
```
- **默认行为**：省略 `dns` 或 `{}` 使用默认链 UDP `8.8.8.8:53` → UDP `1.1.1.1:53` → 系统 DNS。仅设置 `cache_entries` 也使用默认链。显式写 `{"dns":{"server":"system"}}` 时只用系统解析。
- `servers` 为 1..16 项有序字符串数组；保留顺序与重复项，无竞速、排名、隐式排序或去重。不能与旧单值 `server` 并存。旧 `server` 自定义写法视为单个上游，然后系统兜底；`server:"system"` 是显式系统直用。系统不用也不能写入数组。
- 上游字符串：裸 IP/主机名（可带端口，默认 UDP/53）、`udp://host[:port]`、`tcp://host[:port]`、`https://host[:port]/非空路径`（DoH，POST application/dns-message，拒绝重定向，保留标准证书/SNI 校验）。IPv6 带端口须 `[::1]:53`；裸 IPv6 无端口合法。端口 1..65535；拒绝空 host、未知 scheme、URL 用户信息/query/fragment、UDP/TCP 路径。UDP TC 仅降级到同一上游 TCP。
- 每台内部 A/AAAA 并发，但上游之间串行，上一台瞬时失败才尝试下一台，全部失败最后系统仅调用一次。任一族有有效 IP 即使用该台，不为另一族继续查询、不混合跨上游答案。按 A 再 AAAA 及答复顺序去重，最多 16 地址。
- 无 IP 时：经完整 ID/问题/响应/资源/CNAME 边界校验的 NXDOMAIN 终局；两个有效无地址族结果终局；一族空但另一族超时/网络错误/SERVFAIL/坏报文等仍可继续。有 IP 优先于另一族负结果。不做负缓存。
- 整链（含系统兜底和上游域名 bootstrap）使用调用剩余总预算一半，保留另一半用于连接。每次尝试分配 `剩余DNS时间 / (尚未尝试的自定义上游数 + 1个系统)`；快速失败的剩余时间继续均分。系统使用最后剩余 DNS 时间。不重置 `dial_timeout`；取消/预算结束立即停止，无额外 DNS 超时配置。
- `cache_entries` 为 0..4096：自定义/新默认链默认 256，0 关闭；显式系统只允许省略或 0。系统未知 TTL，包含兜底结果在内均不加应用缓存；上游域名仅用系统 resolver bootstrap，不递归用自身。
- 自定义只缓存两族均成功 NOERROR 且至少有一个有效地址的完整正结果；部分成功本次可用但不缓存。CNAME 链/地址最小实际 TTL，内部最多 300 秒，TTL 0 不缓存；不做跨报文 CNAME 递归。满时淘汰最早到期项。
- 成功 reload 新请求使用新列表与新缓存；旧代进行中请求和已建连接保留。所有 DoH endpoint 的空闲池随该代释放关闭。非法配置整次拒绝保旧。
