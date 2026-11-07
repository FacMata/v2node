# AnyTLS 稳定性候选

首个稳定性候选基于 cbffed7，仅替换锁定核心的 AnyTLS 流隔离补丁。真实用户长连接、生产部署结果须单独记录。

## 上游整合候选（2026-11-05，未部署）

本分支在已部署的5593d9f基础上合并v2node上游5c2360f，核心合并0061c59f（Xray 26.10.31），保留本地AnyTLS流隔离、拒绝清理、计数、limiter和用户ETag修复。

接受上游SS2022占位密钥长度修复、Go1.27.3、REALITY依赖及默认关闭MPTCP。Freedom改用stream sockopt设置域名策略，但仍与本地默认DNS地址族保持一致。核心保留解析失败的Error级日志，没有采用上游918ad604的Info降级，避免warning日志配置下失去当前诊断指标。

新核心客户端出站默认使用内置CA；依赖系统私有CA的自定义TLS/DoH出站需要单独验证。此变化不等于服务端不能出示既有自签名证书。本分支不自动部署。

## 配置响应基准保护

后续补丁仅接受HTTP 200作为新配置；304只沿用已经验证过的基准。非200、非法JSON、不支持的协议、无效端口、缺失base_config或无效推拉间隔均不更新摘要/ETag。完整解析和基础校验成功后才提交新基准，只有有效响应内容变化才交给既有重载流程。

`event=node_config_rejected` 记录 `node_id`、`http_status`、`stage`，不打印响应体、ETag、API地址或token。原有传输错误路径与context取消语义保持不变；这不是对全项目既有日志的脱敏改造。

此补丁防止A→502/非法响应→A误触发重载，不解决源站6600端口短时拒绝连接，也不提供全局重载的事务回滚。配置应用成功与否仍由原有启动/重载流程处理。

## 诊断事件

- `event=anytls_lifecycle reason=stale_psh_dropped`：已关闭/未知 stream 的迟到数据被丢弃，会话继续。
- `reason=dispatch_rejected`：新 TCP stream 被 dispatcher 拒绝，已经回复错误 SYNACK/FIN 并清理。
- `reason=udp_rejected`：UDP stream 无法解析/分发，仅关闭该 stream。
- `reason=stream_write_error`：目标侧管道失败，仅关闭该 stream。
- `reason=session_read_end`：会话帧读取循环结束（含正常 EOF），不是故障率。
- `reason=heartbeat_timeout`：心跳超时关闭会话。
- `event=connection_rejected reason=user_missing|device_limit`：明确区分 limiter 用户缺失和设备数限制。

以上是每进程固定原因累计计数，首次及每 100 次输出一次；最后一条 count 是下界，最多存在 99 次未输出事件。进程重启后计数归零；不要把某个日志窗口条数当独立事件总数。事件不包含 IP、UUID、访问域名或原始错误文本。仍然存在旧版本继承的其他日志，外发前必须脱敏。

## 次日比较

先确认运行版本与启动时间，然后比较等长窗口、业务流量背景、拒绝类型和 session/stream 事件。`stale_psh_dropped` 出现说明保护分支工作，不等同新增故障。`session_read_end` 包含正常断开，不能单独与旧版零日志比较。DNS empty response 仍可能存在；本版仅对齐默认 IPv4 策略，没有替换系统 DNS 或增加域名采集。

## 本地检查

核心固定版本的 AnyTLS race 回归；v2node limiter、API ETag、dispatcher、core及node编译/回归；Linux amd64制品构建。更新和回滚都不能删除 `/var/lib/v2node/traffic`、证书或配置。
