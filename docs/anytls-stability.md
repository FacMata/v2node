# AnyTLS 稳定性候选

本版基于 cbffed7，只替换锁定核心的 AnyTLS 流隔离补丁，不包含更晚的整套上游改动。真实用户长连接、生产部署结果须单独记录。

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
