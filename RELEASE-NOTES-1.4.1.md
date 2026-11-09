# rama-proxy v1.4.1 发布说明

- 发布日期：2026-11-09
- 版本：v1.4.1（上一版本 v1.4.0 / Android versionCode 1400）
- 发布分支：`1.4.1` → 合并到 `main`
- 平台：Android 本地 SOCKS5 客户端为主；`proxy-core` 的心跳与隧道池修复同时影响桌面端和 CLI

## 发布概览

v1.4.1 是补丁版本，主要解决 Android 系统提示应用“阻止睡眠 / 耗电异常”的问题，
并修复两个会导致耗电增加或睡眠后请求失败的 `proxy-core` 缺陷。

## 问题原因

v1.4.0 的前台服务从启动到停止始终持有不带超时的 `PARTIAL_WAKE_LOCK` 和
`WIFI_MODE_FULL_HIGH_PERF` Wi-Fi Lock，即使没有任何代理流量，CPU 也无法进入深度睡眠，
Wi-Fi 也无法进入省电模式。

## 变更

### Android：按流量持有 WakeLock / Wi-Fi Lock

- 前台服务不再在整个生命周期内持锁。
- Rust 监听连接池的 `active` 租约数：有代理连接时立即申请锁；连接全部结束并持续
  30 秒后释放，空闲时允许设备睡眠。
- WakeLock 带 10 分钟超时兜底；有流量期间 Rust 每 2 分钟续期一次。
- Rust 与 Kotlin 之间的调用失败后会在下一秒重试；Rust 运行时退出时主动释放锁。
- 新增 Android 插件命令 `setTrafficActive`。
- 通知文案和界面锁状态说明同步调整；空闲时显示“未持有”属于正常状态。

### proxy-core：睡眠后复用失效隧道

- 空闲隧道的新鲜度判断由 `Instant` 改为墙钟时间。
- `Instant` 使用 `CLOCK_MONOTONIC`，在 Android 挂起期间不计时，长时间睡眠后的空闲隧道
  会被误判为“刚验证过”并直接复用；若 NAT 或服务端已断开，首个请求会失败。
- 修复后，睡眠后的空闲隧道会在复用前先 ping 探测，失效则丢弃并新建。

### proxy-core：心跳通道反复重连

- 客户端等待下一次服务端心跳的超时由 `heartbeat_timeout_secs` 改为
  `heartbeat_interval_secs + heartbeat_timeout_secs`。
- 旧逻辑下客户端只等 10 秒，而服务端每 30 秒推送一次，导致心跳通道每轮超时、
  断开并重新建立（包括 TLS 握手）。
- 服务端与客户端 `heartbeat_interval_secs` 的默认值及配置模板由 30 秒改为 60 秒。

### 文档

- 更新 `docs/PROJECT-NOTES.md` 第 5 节和 `proxy-mobile/README.md` 的后台运行与睡眠说明。

## 验证

通过的检查：

- `cargo test -p proxy-core --no-fail-fast`（需设置 `NO_COLOR=1`，见已知限制）
- `cargo check -p proxy-core --locked`

尚未执行：

- `rama-proxy-mobile` 的 Android 目标编译和 Gradle `assembleArm64Release`
- 真机熄屏睡眠测试（建议熄屏 30 分钟以上后再访问，并检查 `RamaProxy` logcat 中
  `partial wake lock acquired/released` 与 `discarding stale idle tunnel`）

## 升级说明

- **已部署的服务端配置需要手动修改**：将 `server.toml` 中的 `heartbeat_interval_secs`
  改为 `60`。代码默认值只对未显式配置该项的文件生效。
- 桌面端/CLI 客户端如在 `client.toml` 中显式配置了 `heartbeat_interval_secs = 30`，
  应同步改为 `60`，否则客户端最多只等待 40 秒，会在服务端两次心跳之间超时重连。
- Android 端每次启动使用代码默认值，不需要修改配置。
- 未升级的旧客户端仍存在心跳反复重连问题，建议与服务端一起升级。
- Android 应用必须加入电池优化白名单，否则 Doze 下后台网络会被切断。
- Android 升级包必须与已安装版本使用同一签名证书；`versionCode` 为 `1401`。

## 已知限制

- “有流量”按连接租约数判断，不按字节流动判断。经代理的长连接（WebSocket、SSH、
  浏览器 keep-alive 等）不断开时锁会一直持有，系统仍可能提示耗电。
- 释放锁后 Wi-Fi 进入省电模式，空闲睡眠后首个请求可能需要探测或重建隧道，延迟略增。
- 设备挂起时收到的 TCP 包能否唤醒设备取决于芯片和厂商实现，不作保证。
- 心跳通道连接失败后仍以固定 10 秒间隔重试，未做退避。
- `tcp_pool_warms_without_udp_associate` 测试在终端输出带颜色时会因 ANSI 转义码匹配失败，
  需设置 `NO_COLOR=1` 运行；该问题在 v1.4.0 已存在。
- v1.4.0 的其余已知限制仍然适用。
