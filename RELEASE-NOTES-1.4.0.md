# rama-proxy v1.4.0 发布说明

- 发布日期：2026-11-08
- 版本：v1.4.0（上一桌面/CLI 版本 v1.3.0；Android 上一构建版本 1.3.3 / 1303）
- 发布分支：`1.4.0` → 合并到 `main`
- 平台：Windows 桌面客户端、Linux/Windows 服务端与客户端 CLI、Android 本地 SOCKS5 客户端

## 发布概览

v1.4.0 新增 Android 客户端，并把移动端运行所需的可嵌入客户端 API、TLS CA 导入、
TCP 隧道池诊断、UDP ASSOCIATE、后台保活和有界日志纳入正式发布。Android 端继续
只提供本地 SOCKS5 端口，不包含 VPN/VpnService，也不会自动接管手机全局流量。

## 新增功能

### Android 本地 SOCKS5 客户端

- 新增 `proxy-mobile` 工程，使用 Tauri 2 + SvelteKit + Rust，复用 `proxy-core`。
- 本地监听地址固定为 `127.0.0.1`，默认端口 `1080`，可在界面修改。
- 提供 SOCKS5 `CONNECT`，并可选启用 `UDP ASSOCIATE`。
- 不申请 `BIND_VPN_SERVICE`，不包含 `VpnService`，不实现 VPN、透明代理或全局流量接管。
- Release 包名为 `com.zqliang.ramaproxy`；Debug 包名为
  `com.zqliang.ramaproxy.debug`，两者可以并存但不能互相覆盖升级。
- 支持 `arm64-v8a`、`armeabi-v7a`、`x86`、`x86_64`，Release 构建启用 R8/minify、
  Cargo `--release` 和 16 KB 页对齐。

### TLS 和证书管理

- `proxy-core` 显式使用 `rustls` + `tokio-rustls` 的 ring 后端，移除本地
  `rama-tls-rustls` patch。
- Android 界面提供“选择 PEM 证书”，通过 Android Storage Access Framework 导入
  `.pem`、`.crt` 或 `.cer` 文件。
- 导入的 CA 保存到应用私有目录 `<app_data_dir>/certs/ca.pem`，目录权限 `0700`，
  文件权限 `0600`。
- 支持一个 PEM 文件包含一张或多张 CA；CA 文件最大 `512 KiB`。
- 移动端当前只管理 CA 信任证书，不提供客户端证书/私钥导入。
- 启用 TLS 时必须先导入 CA；`tls.insecure_skip_verify` 仍会被拒绝。

### TCP 隧道池、心跳和诊断

- 新增 `run_with_shutdown`、`run_with_shutdown_ready` 和
  `run_with_shutdown_ready_and_pool_stats`，便于 Android 等嵌入场景管理客户端生命周期。
- TCP 池支持启动预热、定时补池、连续失败退避、陈旧隧道探测和清理。
- 界面新增连接池诊断字段：`idle`、`connecting`、`active`、
  `consecutiveFailures`、`lastRefillError`、`lastSuccessAgeSecs`、
  `reapedStaleTotal` 等。
- 服务端统计新增心跳连接数；心跳控制连接与 TCP 数据隧道分别展示。
- TCP 连接池预热与 `UDP ASSOCIATE` 相互独立，不开启 UDP 也会建立空闲 TCP 隧道。

### UDP ASSOCIATE

- 支持 SOCKS5 UDP relay，默认关闭，需要在“高级选项”中手动开启。
- UDP relay 只绑定本地临时端口，并限制为与控制连接相同的来源 IP。
- 不支持 SOCKS5 UDP 分片，`FRAG != 0` 的数据报会被拒绝。
- 上游 Rama server 必须支持 UDP tunnel/relay，端到端 UDP 才能工作。

### Android 后台运行和睡眠处理

- 使用非 VPN 的 `specialUse` 前台服务维持本地 SOCKS5。
- 配置 `START_STICKY`、`PARTIAL_WAKE_LOCK` 和高性能 Wi-Fi Lock，并提供电池优化豁免入口。
- 应用从最近任务划掉时不主动停止前台服务。
- 下次打开或回到前台时，根据 `resume.intent` 检测上次运行状态并尝试恢复本地 SOCKS5。
- `START_STICKY` 只能帮助 Android 重建 Kotlin 前台服务，不能重新创建已被系统杀掉的
  Rust/Tauri 运行时；厂商省电策略仍可能导致整个进程退出。

### 有界日志

- 内存日志最多保留 `1,000` 行。
- 界面只显示最近 `300` 行，默认每 `2` 秒刷新。
- 当前日志文件位于 `<app_data_dir>/rama-proxy.log`。
- 文件达到 `2 MiB` 后轮转为 `rama-proxy.log.1`，磁盘最多保留两个文件，总量约不超过
  `4 MiB`。
- 清空日志会同时清理内存缓冲、当前日志和轮转文件。
- Android Logcat 标签为 `RamaProxy`。

### 文档和构建

- 新增根目录 `README.md`，说明桌面端、核心 CLI 和 Android 端的边界。
- 新增 `docs/PROJECT-NOTES.md`，记录构建、签名、TLS、UDP、TCP 池、日志、睡眠和诊断注意事项。
- 完善 `proxy-mobile/README.md` 的 Android Studio、命令行构建、APK 验证和故障排查说明。

## 修复和行为调整

- 修复移动端只看到心跳连接、但 TCP 池未正常展示的问题：补齐连接池预热、补池状态和诊断信息。
- 修复版本信息分散的问题：workspace、移动端 Rust/Tauri、`package.json` 和
  `package-lock.json` 统一为 `1.4.0`，Android `versionCode` 为 `1400`。
- 修复 Android Release 安装失败排查文档，明确“该安装包未包含任何证书”表示使用了未签名 APK，
  应安装 `app-arm64-release.apk`，不要安装 `app-arm64-release-unsigned.apk`。
- 移动端 TLS 配置不再允许通过跳过证书校验规避 CA 配置问题。

## 构建和验证记录

已验证环境：

- JDK 17：`D:\app\Java\jdk-17.0.12`
- Android SDK Platform：36
- Android Build Tools：36.0.0
- NDK：27.2.12479018
- Android 目标：`arm64-v8a`
- Rust Release 构建：Gradle `assembleArm64Release`

通过的检查：

- `cargo fmt --all -- --check`
- `cargo check -p proxy-core -p rama-proxy-mobile`
- `cargo test -p proxy-core --test udp_associate -- --nocapture`
- `cargo test -p proxy-core`
- `npm run check`
- `npm run build`
- Gradle `assembleArm64Release`
- APK `apksigner verify`
- APK `zipalign -c -P 16 -v 4`

Release APK：

- 路径：`E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android\app\build\outputs\apk\arm64\release\app-arm64-release.apk`
- 包名：`com.zqliang.ramaproxy`
- versionName：`1.4.0`
- versionCode：`1400`
- ABI：`arm64-v8a`
- 大小：`12,368,467` 字节（约 `11.80 MiB`）
- SHA-256：`F977ED29F184A58B72E45ACFDB461B49A2434325A26342AA212246B3DCDA5D56`
- 签名：APK Signature Scheme v2 验证通过
- 签名证书 SHA-256：`b8845c1581fd8588f7b56b07f955940bcdf32d196138d48dd1074b64bef0fd0d`
- 权限检查确认不包含 `android.permission.BIND_VPN_SERVICE`

## 升级说明

- 现有 `config/client.toml` 和 `config/server.toml` 不需要因本版本手工迁移。
- Android 升级包必须与本机已安装版本使用同一签名证书。
- 安装正式包请使用 `app-arm64-release.apk`；`*-release-unsigned.apk` 不能用于安装或发布。
- 启用 TLS 的移动端用户需要先在应用内选择 PEM CA，再启动本地 SOCKS5。
- 需要 UDP 的用户应确认上游服务端支持 UDP tunnel，再在高级选项中开启 UDP ASSOCIATE。

## 已知限制

- Android 端不提供 VPN/VpnService，不能自动接管全系统流量；目标应用需手动配置
  `127.0.0.1:<端口>`。
- 本地 SOCKS5 固定无认证，不得直接暴露到局域网或公网。
- UDP 不支持分片，且依赖上游服务端 UDP relay。
- 移动端 TLS 只支持 PEM CA 导入，不支持客户端证书/私钥。
- 前台服务、WakeLock 和 Wi-Fi Lock 不能绕过厂商省电策略，也不能保证进程永不被杀。
- `START_STICKY` 不会自动重建 Rust/Tauri 运行时，需要用户重新打开应用触发恢复。
- 日志采用有界内存和有界磁盘轮转，不适合作为长期审计存储。
- Release 升级必须保持签名证书不变；丢失 keystore 后不能覆盖升级已有安装。