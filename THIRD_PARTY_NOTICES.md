# 第三方组件与二进制分发说明

Kat 自研代码保留所有权利；下述第三方组件继续适用各自原许可。此说明不替代原始法律文本，也不限制第三方许可授予的权利。

## 保留依赖与许可

`third_party/licenses/` 保留当前纯正式入站+直连转发服务端实际链接或引用的组件原始许可与专利文本：

- Go 标准库（BSD-3-Clause）：`third_party/licenses/go-BSD.txt`
- `golang.org/x/crypto v0.57.0`（BSD-3-Clause）：`third_party/licenses/golang.org_x_crypto@v0.57.0-LICENSE`、`third_party/licenses/golang.org_x_crypto@v0.57.0-PATENTS`
- `golang.org/x/net v0.60.0`（BSD-3-Clause）：`third_party/licenses/golang.org_x_net@v0.60.0-LICENSE`、`third_party/licenses/golang.org_x_net@v0.60.0-PATENTS`
- `golang.org/x/sys v0.48.0`（BSD-3-Clause）：`third_party/licenses/golang.org_x_sys@v0.48.0-LICENSE`、`third_party/licenses/golang.org_x_sys@v0.48.0-PATENTS`
- `lukechampine.com/blake3 v1.4.1`（MIT）：`third_party/licenses/lukechampine.com_blake3@v1.4.1-LICENSE`、`third_party/licenses/blake3-MIT.txt`
- `github.com/klauspost/cpuid/v2 v2.0.9`（MIT，BLAKE3 间接依赖）：`third_party/licenses/github.com_klauspost_cpuid_v2@v2.0.9-LICENSE`、`third_party/licenses/cpuid-MIT.txt`

实际编译版本以 `go.mod`、`go.sum` 和二进制构建信息为准。已移除实验性协议与客户端式出站/路由/规则库/订阅相关的第三方依赖（`xtls/reality`、`coder/websocket`、`refraction-networking/utls`、`klauspost/compress`、`oschwald/maxminddb-golang`、`gopkg.in/yaml.v3`、`juju/ratelimit`、`pires/go-proxyproto` 等）。
