# rama-proxy v1.4.2 发布说明

- 发布日期：2026-11-13
- 版本：v1.4.2（上一版本 v1.4.1 / Android versionCode 1401）
- 发布分支：`1.4.2`（基于 `1.4.1`）
- 平台：Android 本地 SOCKS5 客户端
- 版本状态：源码版本已统一为 `1.4.2`，Android `versionCode` 为 `1402`；按本次要求未重新构建安装包

## 发布概览

v1.4.2 是 Android 前台服务恢复修复，解决系统回收并重建 Rama Proxy 进程或前台服务后，
本地 SOCKS5 端口没有恢复，导致使用 `127.0.0.1:1080` 的其他代理/VPN 前端全部断流的问题。

该问题不是 Google Play 特例。Google Play 只是本次观察到断流的上层应用；其他连接本地
SOCKS5 端口的应用也会受到同样影响。

## 问题现象

- Android 后台回收 Rama Proxy 后，Google Play 直接打开时没有经过代理。
- 重新打开 Rama Proxy 后，流量才恢复通过本地 SOCKS5。
- 另一个 VPN/代理前端固定使用 `127.0.0.1:1080`；Rama Proxy 的本地端口消失后，
  该前端的全部流量都会失败。

## 问题原因

- 前台服务使用 `START_STICKY`。Android 重建服务时通常传入空 `intent`。
- 旧实现能够重建 Kotlin 前台服务，但没有在该路径恢复 Rust SOCKS5 runtime。
- Rust runtime 不存在时，`127.0.0.1:1080` 不会被监听；上层代理前端虽然仍在运行，
  但所有连接都会失败。
- 旧兜底逻辑只在用户重新打开应用或应用回到前台时，根据 `resume.intent` 恢复。

## 变更

### Android Sticky Service 自动恢复 Rust runtime

- `ProxyForegroundService.onStartCommand` 将 `intent == null` 识别为系统重建。
- Service 加载 native 库并调用 `nativeRuntimeBridge(dataDir, true)`，不再只重建 Kotlin 外壳。
- Rust 从应用数据目录读取 `resume.intent`、`client.toml` 和 `rama-proxy.log`，重新初始化日志并启动 SOCKS5 runtime。
- Tauri 启动与 JNI 恢复共用进程级 `SERVICE_STATE`；恢复过程串行化，避免并发重复绑定 `127.0.0.1:1080`。
- Rust 恢复完成后回调 Service，更新运行状态、通知、WakeLock/Wi-Fi Lock 和界面状态。

### 恢复状态与前端兜底

- Android 插件状态新增 `restoreInProgress` 和 `restoreError`。
- 前端新增 `foregroundServiceRestoring`，避免 Service 自动恢复期间重复发起启动。
- 通知和界面显示“恢复中”；失败时展示具体原因，并保留打开应用/回到前台后的兜底恢复。
- 没有新增 `VpnService`，不接管系统全局流量，也不会强制拉起 Activity。

### 版本与文档

- 根 workspace、移动端 Rust/Tauri、`package.json`、`package-lock.json` 和 Android 配置统一为 `1.4.2` / `1402`。
- 更新根 README、`docs/PROJECT-NOTES.md`、`proxy-mobile/README.md` 和 `proxy-core/README.md`。

## 验证

已通过：

- `cargo fmt --all -- --check`
- `cargo check -p rama-proxy-mobile`
- `npm run check`（0 errors / 0 warnings）
- `cargo check --target aarch64-linux-android -p rama-proxy-mobile`
- Android Debug 和 Release 完整构建
- Release 经 R8 后保留 JNI 方法及 Rust 回调
- 原生库保留 JNI 导出符号 `Java_com_zqliang_ramaproxy_ProxyForegroundService_nativeRuntimeBridge`

版本号提升前的验证 APK：

- 路径：`proxy-mobile/src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release.apk`
- 包名：`com.zqliang.ramaproxy`
- 版本：`1.4.1`，`versionCode 1401`
- 大小：`40,423,129` 字节
- SHA-256：`14E7562E0028F9C6196C4C368AA12F1B5D18DC0BB89602D3810A2820BEAD6E86`
- APK Signature Scheme v2：通过
- 签名证书 SHA-256：`b8845c1581fd8588f7b56b07f955940bcdf32d196138d48dd1074b64bef0fd0d`

上述 APK 是版本号提升前的验证产物，不是最终 v1.4.2 发布包。按本次要求没有重新打包。

尚未执行：

- 未连接 Android 真机，未实际验证厂商 ROM 下 `START_STICKY` 重建后的自动恢复。
- 未验证强制停止、系统禁止自启动和长时间后台冻结场景。

## 升级说明

- 正式发布前必须使用 `1.4.2` / `versionCode 1402` 重新构建并签名 APK。
- 升级包必须继续使用现有签名证书；证书不一致会无法覆盖安装。
- 建议允许应用自启动、后台运行，并关闭针对本应用的电池优化限制。
- 如果系统彻底杀掉整个进程但不再重建 Service，仍需手动打开应用恢复代理。

## 已知限制

- `START_STICKY` 不保证 Service 一定被系统重建；强制停止、厂商禁止自启动或激进省电策略仍可能阻止恢复。
- 自动恢复依赖 `resume.intent` 和有效的 `client.toml`。标记或配置缺失、native 库加载失败、端口绑定失败时会显示 `restoreError`。
- 自动恢复只负责恢复本地 SOCKS5 runtime，不能修复上游网络、TLS 证书或服务端不可达等外部故障。
- v1.4.1 的 WakeLock、睡眠后隧道探测和心跳限制仍然适用。
