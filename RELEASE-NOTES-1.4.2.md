# rama-proxy v1.4.2 发布说明

- 发布日期：2026-11-21
- 版本：v1.4.2（上一版本 v1.4.1 / Android versionCode 1401）
- 发布分支：`1.4.2`（基于 `1.4.1`）
- 平台：Android 客户端、Windows 桌面客户端和 `proxy-core` 服务端
- 版本状态：源码版本已统一为 `1.4.2`，Android `versionCode` 为 `1402`

## 发布概览

v1.4.2 首次发布包含两部分核心改进。2026-11-26 的分支更新补充了代理诊断、Windows 控制台和服务端转发修复。

1. **Android 前台服务恢复修复**：解决系统回收并重建 Rama Proxy 进程或前台服务后，本地 SOCKS5 端口没有恢复，导致使用 `127.0.0.1:1080` 的其他代理/VPN 前端或数据采集应用全部断流的问题。
2. **数据采集场景深度功耗优化与消除“后台频繁刷新”告警**：消除 Android 系统电池管理提示 **“Frequently refreshes in the background. Force stop to save power.”（后台频繁刷新）** 及 ~234 mAh 的后台射频待机耗电，同时通过 **1 条常驻热备隧道 + Android `ConnectivityManager.NetworkCallback` 网络事件驱动秒级重连** 确保代理时刻具备可用网络连接。

## 问题现象与原因

### 1. 前台服务重建后本地 SOCKS5 端口未恢复

- 前台服务使用 `START_STICKY`。Android 重建服务时通常传入空 `intent`。
- 旧实现能够重建 Kotlin 前台服务，但没有在该路径恢复 Rust SOCKS5 runtime。
- Rust runtime 不存在时，`127.0.0.1:1080` 不会被监听；上层代理或采集客户端虽然仍在运行，但所有连接都会失败，直到用户手动重新打开应用触发 `resume.intent` 恢复。

### 2. Android 告警“Frequently refreshes in the background”与后台射频高耗电

- **60 秒独立心跳通道全天候唤醒无线射频**：旧逻辑下客户端维持一条独立的心跳控制连接，每 60 秒接收服务端 `OP_HEARTBEAT` 并回复 `OP_HEARTBEAT_ACK`（每天 1,440 次后台网络收发），且每次写入 `INFO` 日志。在 5G/Wi-Fi 下，每分钟一次的网络包会使基带/射频反复进入 10~15 秒的高功耗 Tail 状态（CPU 仅运行 2 分钟却消耗 233.90 mAh 电量），并触发 Android 厂商电源管理（PowerGenie 等）的“后台频繁刷新”检测。
- **HTTP Keep-Alive 空闲连接长期持锁**：v1.4.1 按连接池 `active > 0`（租约数）判断是否持锁。数据采集客户端（OkHttp、浏览器/WebView、采集脚本等）在批次间隔期间保持 HTTP keep-alive 连接不关闭，导致即使没有任何字节传输，`PARTIAL_WAKE_LOCK` 和 Wi-Fi Lock 也会一直持有。
- **Wi-Fi 锁模式过高**：Android 10+ 下使用了 `WIFI_MODE_FULL_LOW_LATENCY`，完全禁用了 Wi-Fi 省电机制（DTIM/PSM）。
- **深度空闲期维持多条空闲连接与高频轮询**：无流量时仍维持 `poolSize`（默认 4 条）空闲连接并高频轮询状态。
- **每次日志写入执行同步文件 `stat` + `open` + `write` + `close`**：单次 SOCKS5 请求默认输出 4 条 `INFO` 日志，每条日志都在异步工作线程上同步打开和关闭 `rama-proxy.log`。

## 变更

### Android Sticky Service 自动恢复 Rust runtime

- `ProxyForegroundService.onStartCommand` 将 `intent == null` 识别为系统重建。
- Service 加载 native 库并调用 `nativeRuntimeBridge(dataDir, true)`，不再只重建 Kotlin 外壳。
- Rust 从应用数据目录读取 `resume.intent`、`client.toml` 和 `rama-proxy.log`，重新初始化日志并启动 SOCKS5 runtime。
- Tauri 启动与 JNI 恢复共用进程级 `SERVICE_STATE`；恢复过程串行化，避免并发重复绑定 `127.0.0.1:1080`。
- Rust 恢复完成后回调 Service，更新运行状态、通知、WakeLock/Wi-Fi Lock 和界面状态。
- Android 插件状态新增 `restoreInProgress` 和 `restoreError`；前端新增 `foregroundServiceRestoring`，避免 Service 自动恢复期间重复发起启动。

### Android & proxy-core：消除后台频繁刷新告警并保证网络时刻在线

- **移动端关闭冗余 60 秒心跳控制通道**：`TunnelPool` 本身已具备隧道预热、探测与自动补池能力；移动端将 `heartbeat_interval_secs` 设为 `0` 关闭冗余的每分钟心跳通道（桌面端/服务端仍保留原默认值，且支持指数退避重连 `10s -> 300s` 并下调心跳快照日志为 `debug!`）。
- **深度空闲单隧道热备（Always-Connected Standby）**：
  - 活跃期及流量结束后 3 分钟内，维持完整的 `poolSize`（如 4 条）热备连接池。
  - 无代理流量超过 3 分钟后进入深度空闲（Deep Idle）：自动收缩多余空闲隧道，**始终保留 1 条已验证的在线热备隧道**，并将后台探测周期放宽至 **10 分钟**（同时为隧道配置 300 秒 TCP Keepalive）。一旦有新请求到来，立即复用该热备隧道并瞬间扩容回完整 `poolSize`。
- **Android 系统网络切换事件驱动秒级重连（`ConnectivityManager.NetworkCallback`）**：
  - `ProxyForegroundService` 注册系统默认网络监听（新增 `ACCESS_NETWORK_STATE` 权限），当 Wi-Fi / 5G 切换或设备唤醒网络恢复（`onAvailable`）时，通过 JNI `nativeNotifyNetworkAvailable` 立即唤醒 Rust 连接池重置退避、校验旧连接并补充新隧道，无需高频定时器轮询即可保证网络时刻连通。
- **按实际字节流量持锁与 10 秒快速释锁**：
  - `TunnelLease` 在 `poll_read` / `poll_write` 实际读写字节时更新原子时间戳 `last_traffic_unix_ms`（暴露为 `lastTrafficAgeSecs`）。
  - Android `drive_traffic_locks` 改为按 `lastTrafficAgeSecs < 10` 持有 `PARTIAL_WAKE_LOCK` 和 Wi-Fi Lock：字节停止流动 10 秒后立即释放锁，即使采集器保持 HTTP keep-alive 连接不关也不会阻止手机休眠。
  - 新增本地 SOCKS5 TCP 转发空闲超时（`TCP_RELAY_IDLE_TIMEOUT = 180s`），自动回收长期无数据收发的僵尸连接。
  - `ProxyForegroundService` 的 Wi-Fi Lock 统一改为 `WIFI_MODE_FULL_HIGH_PERF`，不再使用高耗电的 `WIFI_MODE_FULL_LOW_LATENCY`。

### proxy-mobile & proxy-core：日志常驻缓冲写入与级别降噪

- `rama-proxy.log` 改为常驻 `BufWriter<File>` + 内存字节计数判断轮转，避免每条日志产生 `metadata` + `open` + `close` 系统调用；遇到 `WARN` / `ERROR` 或轮转时立即 `flush`。
- 将单次 SOCKS5 连接的 4 条生命周期日志（`accepted`、`received`、`connected`、`finished`）从 `info!` 下调为 `debug!`，大幅降低高频数据采集时的闪存写入与 Logcat IPC 开销。
- `proxy-core` 默认日志初始化禁用 ANSI 颜色转义（`with_ansi(false)`），修复终端彩色输出环境下 `tcp_pool_warms_without_udp_associate` 测试的日志匹配问题。

### 版本与文档

- 根 workspace、移动端 Rust/Tauri、`package.json`、`package-lock.json` 和 Android 配置统一为 `1.4.2` / `1402`。
- 更新根 README、`docs/PROJECT-NOTES.md`、`proxy-mobile/README.md` 和 `proxy-core/README.md`。

## 2026-11-26 分支更新

### 服务端转发与连接管理

- TLS 握手失败或超时会清理活跃连接记录，错误日志带 `connection_id`。关闭通知只发给指定连接，其他隧道可以继续转发。
- TCP 双向转发支持半关闭。一端结束发送后，另一端仍可传完剩余数据。单条隧道双向连续 180 秒无数据时自动回收。
- 客户端和目标站两侧的 TCP 套接字启用 `TCP_NODELAY` 和 keepalive。单条连接设置失败时记录告警，服务端继续监听。
- UDP 上行每个数据包只获取一次统计写锁。地址在生成快照时才格式化，快照在锁外排序。

### 拨号诊断

- 客户端隧道日志拆分 TCP、TLS 和认证阶段。SOCKS5 CONNECT 记录是否命中预热池、取隧道耗时和等待目标建连的耗时。
- 服务端拨号日志记录 `dns_ms`、`tcp_phase_ms` 和 `dial_ms`。`tcp_phase_ms` 包含 DNS 完成后的调度及地址重试。通过 `connection_id` 和客户端的 `server_connection_id` 对照两侧日志。
- 成功拨号达到 500 ms 时记 INFO，更快的连接记 DEBUG。排查时可将服务端 `log.level` 设为 `info,proxy_core::server_runtime::dial=debug`，查看全部目标拨号记录。
- `proxy-core` 和移动端日志使用紧凑格式。

### Windows 桌面客户端

- 控制台支持滚轮、滚动条、跟随最新日志和复制全部保留日志。清空日志时重置滚动位置。
- 本地 SOCKS5 和独立 HTTP CONNECT 使用独占端口监听，防止多个实例同时绑定同一端口。

## 验证

已通过：

- `cargo fmt --all -- --check`
- `cargo check -p proxy-core -p rama-proxy-mobile`
- `cargo test -p proxy-core`（含 `socks5_udp_associate_relays_datagrams_end_to_end` 与 `tcp_pool_warms_without_udp_associate`）

## 升级说明

- 正式发布前必须使用 `1.4.2` / `versionCode 1402` 重新构建并签名 APK。
- 升级包必须继续使用现有签名证书；证书不一致会无法覆盖安装。
- 建议允许应用自启动、后台运行，并关闭针对本应用的电池优化限制。
- 如需在日志中查看逐连接的 SOCKS5 握手与转发完成记录，可将 `RAMA_PROXY_LOG` 或配置文件中的 `log.level` 设为 `debug`。
- 已有 GUI 可以连接新版服务端。单独升级服务端时只需更新服务端 `proxy-core`。如需新的 Windows 控制台和独占端口行为，可从当前分支重新构建 Windows 客户端。

## 已知限制

- `START_STICKY` 不保证 Service 一定被系统重建；强制停止、厂商禁止自启动或激进省电策略仍可能阻止恢复。
- 自动恢复依赖 `resume.intent` 和有效的 `client.toml`。标记或配置缺失、native 库加载失败、端口绑定失败时会显示 `restoreError`。
- 自动恢复只负责恢复本地 SOCKS5 runtime，不能修复上游网络、TLS 证书或服务端不可达等外部故障。
- 深度空闲期连接池显示的 `warmIdleTarget` 和 `idle` 为 `1` 属于正常省电热备状态，有流量时会立即恢复为配置的 `poolSize`。
