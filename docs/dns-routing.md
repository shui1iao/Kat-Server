# DNS 与基础直连规则

DNS 部分反映 dev-0.7 当前开发改进（未发布、未部署）；完整出站与规则语法见 README。下方 Routing 节保留旧式直连/拒绝规则的兼容语义。

## DNS
```json
{"dns":{"servers":["udp://8.8.8.8:53","udp://1.1.1.1:53"],"cache_entries":256}}
```
- **默认行为变更**：省略 `dns` 或 `{}` 不再是系统直用，而是 UDP `8.8.8.8:53` → UDP `1.1.1.1:53` → 系统 DNS。仅设置 `cache_entries` 也使用默认链。旧配置需要原行为时显式写 `{"dns":{"server":"system"}}`。
- `servers` 为 1..16 项有序字符串数组；保留顺序与重复项，无竞速、排名、隐式排序或去重。不能与旧单值 `server` 并存。旧 `server` 自定义写法视为单个上游，然后系统兜底；`server:"system"` 是显式系统直用。系统不用也不能写入数组。
- 上游字符串：裸 IP/主机名（可带端口，默认 UDP/53）、`udp://host[:port]`、`tcp://host[:port]`、`https://host[:port]/非空路径`。IPv6 带端口须 `[::1]:53`；裸 IPv6 无端口合法。端口 1..65535；拒绝空 host、未知 scheme、URL 用户信息/query/fragment、UDP/TCP 路径。DoH 使用 POST application/dns-message，拒绝重定向，保留标准证书/SNI 校验。UDP TC 仅降级到同一上游 TCP。
- 每台内部 A/AAAA 并发，但上游之间串行，上一台瞬时失败才尝试下一台，全部失败最后系统仅调用一次。任一族有有效 IP 即使用该台，不为另一族继续查询、不混合跨上游答案。按 A 再 AAAA 及答复顺序去重，最多 16 地址。
- 无 IP 时：经完整 ID/问题/响应/资源/CNAME 边界校验的 NXDOMAIN 终局；两个有效无地址族结果终局；一族空但另一族超时/网络错误/SERVFAIL/坏报文等仍可继续。有 IP 优先于另一族负结果。不做负缓存。
- 整链（含系统兜底和上游域名 bootstrap）使用调用剩余总预算一半，保留另一半用于连接。每次尝试分配 `剩余DNS时间 / (尚未尝试的自定义上游数 + 1个系统)`；快速失败的剩余时间继续均分。系统使用最后剩余 DNS 时间。不重置 `dial_timeout`；取消/预算结束立即停止，无额外 DNS 超时配置。默认 5 秒拨号预算下，DNS 链约不超过 2.5 秒（等待并发额度也计入调用总预算）。调度/清理有少量开销，不是实时硬保证。
- `cache_entries` 为 0..4096：自定义/新默认链默认 256，0 关闭；显式系统只允许省略或 0。系统未知 TTL，包含兜底结果在内均不加应用缓存；上游域名仅用系统 resolver bootstrap，不递归用自身。
- 自定义只缓存两族均成功 NOERROR 且至少有一个有效地址的完整正结果；部分成功本次可用但不缓存。CNAME 链/地址最小实际 TTL，内部最多 300 秒，TTL 0 不缓存；不做跨报文 CNAME 递归。满时淘汰最早到期项。每代 64 lookup 槽，最多 128 同时 family worker；串行重试不叠加 worker。
- 成功 reload 新请求使用新列表与新缓存；旧代进行中请求和已建连接保留。所有 DoH endpoint 的空闲池随该代释放关闭。非法配置整次拒绝保旧。

## Routing
```json
{"routing":{"rules":[
 {"domain":"blocked.example","action":"reject"},
 {"domain_suffix":"allowed.example","action":"direct"},
 {"ip_cidr":"192.0.2.0/24","action":"reject"}
]}}
```
- 省略routing、`{}`或rules=[]均无规则，默认direct。最多1024条。
- 每条须action为`direct`或`reject`，且**恰有一个**选择器`domain`/`domain_suffix`/`ip_cidr`，不允许其它字段。
- domain/suffix为ASCII DNS名（IDN先转punycode），标签1..63、总长≤253；忽略大小写，允许一个末尾点；不允许通配符/前导点/空标签。suffix匹配本域及点边界子域，不是任意字符串尾缀。
- ip_cidr为合法IPv4/IPv6前缀；内部mask规范化，IPv4-mapped一致处理。
- **单一列表首匹配**：每个候选从第1条开始，以原目标域名（如有）和当前literal IP匹配，首条决定，未命中direct。domain direct能覆盖后置CIDR reject，前置CIDR也能覆盖后置domain动作。裸IP不匹配domain。
- **有条件DNS前拒绝**：命中的domain reject之前没有待IP判定的CIDR时可零DNS拒绝；前置CIDR可能决定结果时须解析后按原顺序决定，不承诺任意位置domain reject均不查询。
- 多IP逐候选决策，被拒IP绝不连接/发送，其它允许候选可继续。TCP按允许顺序literal拨号；UDP选择首个允许且有出站socket地址族的IP。全拒绝失败。绝不检查一个IP后重新Dial业务hostname。
- 显式 `server:"system"` 且无有效 rules 时保留原 TCP 系统 Dialer/UDP 系统解析路径；省略 dns 使用新默认链。

## 严格形状与例子
合法（可选块片段，合并到已有有效配置）：
```json
{"dns":{"servers":["8.8.8.8","1.1.1.1"]}}
{"dns":{"server":"dns.google:53","cache_entries":0}}
{"dns":{"server":"tcp://dns.google:53"},"routing":{"rules":[]}}
{"dns":{"server":"system"},"routing":{"rules":[{"ip_cidr":"::/0","action":"reject"}]}}
```
非法还包括：`servers:[]/null`、`servers:[null/""/"system"]`、同时 `server` 与 `servers`、超过16项数组；`dns:null`、`routing:null`、`server:[]`、`cache_entries:-1/4097/1.5/null`、`server:""`、system+非零cache、`rules:null`/非数组、规则缺action/缺选择器/多个选择器/未知键/坏CIDR/坏动作、域名`*.example`/`.example`/空标签。块和内部未知字段一律拒绝，不静默忽略。

DNS 限制：只有内部解析，不监听客户端 DNS；无按业务域名选 DNS、DNS 代理出站、DoT/HTTP3 或 FakeIP。现有SS5m双向idle和精确目标过滤不变；UDP被规则拒绝目标不发送、不进入allowed、不由返回包续命。
