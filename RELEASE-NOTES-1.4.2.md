# rama-proxy v1.4.2 发布说明

- 发布日期：2026-11-19
- 版本：v1.4.2（上一版本 v1.4.1 / Android versionCode 1401）
- 发布分支：`1.4.2`（基于 `1.4.1`）
- 平台：Android 本地 SOCKS5 客户端与 `proxy-core` 功耗及性能优化
- 版本状态：源码版本已统一为 `1.4.2`，Android `versionCode` 为 `1402`

## 发布概览

v1.4.2 包含两部分核心改进：

1. **Android 前台服务恢复修复**：解决系统回收并重建 Rama Proxy 进程或前台服务后，本地 SOCKS5 端口没有恢复，导致使用 `127.0.0.1:1080` 的其他代理/VPN 前端或数据采集应用全部断流的问题。
2. **数据采集场景功耗与运行时效率优化**：解决 HTTP keep-alive 空闲连接长期阻止设备休眠、Wi-Fi 低延迟锁过度耗电、后台无流量时定时轮询与网络探测频繁唤醒 CPU/射频，以及高频请求下日志文件频繁同步打开/关闭带来的磁盘 I/O 开销。

## 问题现象与原因

### 1. 前台服务重建后本地 SOCKS5 端口未恢复

- 前台服务使用 `START_STICKY`。Android 重建服务时通常传入空 `intent`。
- 旧实现能够重建 Kotlin 前台服务，但没有在该路径恢复 Rust SOCKS5 runtime。
- Rust runtime 不存在时，`127.0.0.1:1080` 不会被监听；上层代理或采集客户端虽然仍在运行，但所有连接都会失败，直到用户手动重新打开应用触发 `resume.intent` 恢复。

### 2. 数据采集批次间隔与空闲期耗电偏高

- **HTTP Keep-Alive 空闲连接长期持锁**：v1.4.1 按连接池 `active > 0`（租约数）判断是否持锁。数据采集客户端（OkHttp、浏览器/WebView、采集脚本等）在批次间隔期间会保持 HTTP keep-alive 连接不关闭，导致即使没有任何字节传输，`PARTIAL_WAKE_LOCK` 和 Wi-Fi Lock 也会一直持有。
- **Wi-Fi 锁模式过高**：Android 10+ 下使用了 `WIFI_MODE_FULL_LOW_LATENCY`，完全禁用了 Wi-Fi 省电机制（DTIM/PSM），导致无线射频持续处于高功耗状态。
- **空闲时后台轮询与网络探测频繁唤醒**：
  - `stats_task` 在无连接时仍每 5 秒轮询并无条件向 `watch::channel` 发送通知，唤醒锁驱动协程。
  - 连接池维护任务在长时间无业务流量时仍每 30 秒唤醒、每 2 分钟对所有空闲隧道发送网络 Ping/Pong 探测包，阻碍基带与 CPU 深度休眠。
- **每次日志写入执行同步文件 `stat` + `open` + `write` + `close`**：单次 SOCKS5 请求默认输出 4 条 `INFO` 日志，每条日志都在异步工作线程上同步打开和关闭 `rama-proxy.log`。

## 变更

### Android Sticky Service 自动恢复 Rust runtime

- `ProxyForegroundService.onStartCommand` 将 `intent == null` 识别为系统重建。
- Service 加载 native 库并调用 `nativeRuntimeBridge(dataDir, true)`，不再只重建 Kotlin 外壳。
- Rust 从应用数据目录读取 `resume.intent`、`client.toml` 和 `rama-proxy.log`，重新初始化日志并启动 SOCKS5 runtime。
- Tauri 启动与 JNI 恢复共用进程级 `SERVICE_STATE`；恢复过程串行化，避免并发重复绑定 `127.0.0.1:1080`。
- Rust 恢复完成后回调 Service，更新运行状态、通知、WakeLock/Wi-Fi Lock 和界面状态。
- Android 插件状态新增 `restoreInProgress` 和 `restoreError`；前端新增 `foregroundServiceRestoring`，避免 Service 自动恢复期间重复发起启动。

### Android & proxy-core：按实际字节流量持锁与空闲连接回收

- `TunnelLease` 在 `poll_read` / `poll_write` 实际读写字节时更新原子时间戳 `last_traffic_unix_ms`，并在 `TunnelPoolSnapshot` 中暴露 `lastTrafficAgeSecs`。
- Android `drive_traffic_locks` 改为按 `lastTrafficAgeSecs < 30` 决定是否持有 `PARTIAL_WAKE_LOCK` 和 Wi-Fi Lock：即使客户端保持空闲的 HTTP keep-alive 连接，只要超过 30 秒无实际字节流动，即自动释放锁允许设备休眠。
- 新增本地 SOCKS5 TCP 转发空闲超时（`TCP_RELAY_IDLE_TIMEOUT = 180s`），自动关闭长期无数据收发的半开或僵尸 keep-alive 连接并归还隧道租约。
- `ProxyForegroundService` 的 Wi-Fi Lock 统一改为 `WIFI_MODE_FULL_HIGH_PERF`，不再使用高耗电的 `WIFI_MODE_FULL_LOW_LATENCY`。

### proxy-core：事件驱动状态推送与连接池深度空闲（Deep Idle）

- `TunnelPool` 新增 `Notify` 事件通知：在获取隧道、释放租约、补池完成或失败时立即触发通知。
- `stats_task` 改为 `Notify` 事件驱动 + `send_if_modified`（状态未变时不唤醒下游），完全空闲且无退避时轮询间隔退避至 30 秒。
- 连接池维护任务新增 **深度空闲模式（Deep Idle）**：当无代理流量持续超过 3 分钟且连接池已满时，暂停后台主动网络 Ping 探测并将维护间隔延长至 5 分钟（新请求到来时通过 `Notify` 立即唤醒并在 `acquire` 时按需探测）。

### proxy-mobile & proxy-core：日志常驻缓冲写入与级别降噪

- `rama-proxy.log` 改为常驻 `BufWriter<File>` + 内存字节计数判断轮转，避免每条日志产生 `metadata` + `open` + `close` 系统调用；遇到 `WARN` / `ERROR` 或轮转时立即 `flush`。
- 将单次 SOCKS5 连接的 4 条生命周期日志（`accepted`、`received`、`connected`、`finished`）从 `info!` 下调为 `debug!`，大幅降低高频数据采集时的闪存写入与 Logcat IPC 开销。
- `proxy-core` 默认日志初始化禁用 ANSI 颜色转义（`with_ansi(false)`），修复终端彩色输出环境下 `tcp_pool_warms_without_udp_associate` 测试的日志匹配问题。

### 版本与文档

- 根 workspace、移动端 Rust/Tauri、`package.json`、`package-lock.json` 和 Android 配置统一为 `1.4.2` / `1402`。
- 更新根 README、`docs/PROJECT-NOTES.md`、`proxy-mobile/README.md` 和 `proxy-core/README.md`。

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

## 已知限制

- `START_STICKY` 不保证 Service 一定被系统重建；强制停止、厂商禁止自启动或激进省电策略仍可能阻止恢复。
- 自动恢复依赖 `resume.intent` 和有效的 `client.toml`。标记或配置缺失、native 库加载失败、端口绑定失败时会显示 `restoreError`。
- 自动恢复只负责恢复本地 SOCKS5 runtime，不能修复上游网络、TLS 证书或服务端不可达等外部故障。
- 释放锁后 Wi-Fi 进入省电模式，空闲睡眠后首个请求可能需要探测或重建隧道，延迟略增。
