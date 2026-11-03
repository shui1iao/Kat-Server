# Kat-Server v0.7.2

仅发布，不自动部署或升级现有服务。原Kat仓库改名Kat-Server，旧标签/附件保留；命令kat、Go模块路径和Linux附件命名契约不变。

## 本版变化
- DNS默认有序链改为8.8.8.8 → 1.1.1.1 → 系统DNS；支持有序servers，瞬时失败才换上游，有效负答案终止，整链共享预算，遵守真实TTL，reload保旧请求。需要原行为可显式server: system。
- AnyTLS出站池及写队列清尾引用；carrier复用校验实际策略链，旧stream不强断。规则/地理库读取有界预分配。provider拒绝非普通文件并防FIFO阻塞，候选generation准备/提交成功后接受新快照；缓存写失败仍可能告警，不宣称磁盘与运行代完全原子。
- Smart v2：站点学习、真实业务首响应归因、有界自适应拨号、恢复滞回、同身份reload学习继承；完整有效冷首轮之前不自动选择。
- URLTest默认探测间隔10分钟→1分钟，默认tolerance 100ms→20ms；采用稳定样本/确认轮/停留时间；新fixed/damping/smart配置及权重语义。Fallback默认独立两轮失败（显式max_failed_times可配置，例如4），部分/重复/过时样本不算完整失败轮；LB和探测归因、冷依赖与目标预算分离。
- 订阅支持保留节点的dialer-proxy依赖图、受支持URLTest来源组、命名空间和循环校验、include_group/原名筛选。

## 明确不包含
域名下划线校验放宽、DNS policy/hosts、SS obfs/http、单资源手动刷新API、桌面客户端功能。Windows客户端core不是此Linux入口的可互换产品。

## 验证与权利
本次在Hytron隔离执行group/AnyTLS/provider/route回归与race、kernel Chain/Provider/DNS/Reload回归与race，以及Linux完整构建；旧测试按已接受冷首轮/独立失败轮契约适配，保留原失败记录。DoH证书测试改用独立Transport消除fixture并发修改，不改DNS生产语义。未部署现网或Bero，不宣称所有协议/生产负载完整验收。

自研代码权利声明及第三方原许可不变；对应第三方源码/修改/许可见本tag。
