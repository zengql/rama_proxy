# Rama Proxy 项目注意事项与运维手册

- 文档更新时间：2026-11-08
- 适用范围：仓库根目录、`proxy-core`、`proxy-gui`、`proxy-mobile`
- Android 当前版本：`1.4.0`，版本号 `1400`
- Android Release 包名：`com.zqliang.ramaproxy`
- Android Debug 包名：`com.zqliang.ramaproxy.debug`

本文汇总当前实现中最容易误判、最容易导致构建/安装/运行失败的事项。源码是最终依据；当本文与源码不一致时，以源码和重新验证结果为准，并同步更新本文。

## 1. 项目结构和技术栈

```text
rama_proxy/
├─ proxy-core/        Rust 核心、客户端/服务端 CLI、SOCKS5、UDP、TLS、隧道池、Web UI
├─ proxy-gui/         Windows 桌面 GUI（GPUI，不是 Tauri）
├─ proxy-mobile/      Android 客户端（Tauri 2 + SvelteKit + Rust）
├─ Cargo.toml         Rust workspace
└─ Cargo.lock         锁定 Rust 依赖
```

Android 工程位于：

```text
E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android
```

`proxy-gui` 使用 GPUI，包含 Windows 窗口和托盘逻辑，不能直接作为 Android/Tauri 工程构建。Android 端复用 `proxy-core`，但不是把 `proxy-gui` 直接移植过去。

## 2. Android 功能和安全边界

当前 Android 客户端明确只做本机 SOCKS5 代理：

- 本地监听地址固定为 `127.0.0.1`，不能从界面改成局域网地址。
- 默认 SOCKS5 端口为 `1080`，可以在界面中修改。
- SOCKS5 固定使用无认证模式。
- 支持 SOCKS5 `CONNECT`（TCP）和 `UDP ASSOCIATE`（UDP）。
- UDP 默认关闭，需要在“高级选项”中手动开启。
- 固定关闭 HTTP CONNECT 监听。
- 不申请 `BIND_VPN_SERVICE`，不包含 `VpnService`。
- 不实现 VPN、系统级代理、透明代理或全局流量接管。
- 其他应用必须手动配置本地 SOCKS5 地址，不能依赖 Android 自动把流量送入代理。

因此，Android 系统设置里找不到“Rama Proxy VPN”是预期行为，不是构建失败。检查 APK 时也不应出现 `android.permission.BIND_VPN_SERVICE`。

## 3. 本地监听和配置

界面中的 `serverAddr` 是上游 Rama server 地址，不是手机本地监听地址。实际本地监听地址始终为：

```text
127.0.0.1:<socks5Port>
```

应用配置保存在 Tauri 应用数据目录的 `client.toml`。Android Release 默认禁止明文流量，正式使用应启用 TLS；Debug 构建允许明文，便于联调。

## 4. TCP 连接池与 UDP ASSOCIATE

### 4.1 两者相互独立

TCP 连接池由客户端启动后主动预热和补充，不依赖 SOCKS5 客户端发起 `UDP ASSOCIATE`。已验证以下两个测试均通过：

- `socks5_udp_associate_relays_datagrams_end_to_end`
- `tcp_pool_warms_without_udp_associate`

正常情况下，即使 UDP 关闭，启动 SOCKS5 后也应逐渐出现连接池隧道。预期日志包括：

```text
warm tunnel pool below target; scheduling refill
starting idle tunnel creation
fresh tunnel connection is ready
idle tunnel added to pool
heartbeat tunnel snapshot received
```

如果只看到心跳连接，应检查界面中的连接池诊断字段：

- `idle`：空闲 TCP 隧道数量
- `connecting`：正在建立的隧道数量
- `active`：使用中的隧道数量
- `consecutiveFailures`：连续失败次数
- `lastRefillError`：最近一次补池失败原因
- `lastSuccessAgeSecs`：距离最近一次成功的秒数
- `reapedStaleTotal`：清理失效隧道累计数量

同时搜索日志：

```text
failed to create idle tunnel; refill will back off
failed to create fresh tunnel during acquire fallback
tunnel handshake failed
tls connect failed
```

如果开启 UDP 后连接池“突然正常”，通常是因为这次操作触发保存/重启，使之前失败的预热重新执行，而不是 UDP 本身创建了 TCP 池。应同时看客户端池状态和服务端 `heartbeat tunnel snapshot sent` 中的 `tunnel_count`。

### 4.2 UDP 限制

- UDP relay 绑定在 `127.0.0.1` 的临时端口，不暴露到外部网卡。
- 客户端必须通过 SOCKS5 `UDP ASSOCIATE` 获取 relay 地址。
- relay 只接受与控制连接同一来源 IP 的 UDP 数据报；来源端口也会在首个数据报后被固定。
- 不支持 SOCKS5 UDP 分片；`FRAG != 0` 的数据报会被拒绝。
- 上游 Rama server 必须支持 UDP tunnel/relay，端到端 UDP 才能工作。
- UDP 控制连接和 relay 存在空闲超时，长时间无流量后会关闭。

### 4.3 睡眠后连接消失

手机睡眠后连接全部消失时，不要先归因于 UDP。至少有三类原因：

1. Android 或厂商省电策略杀掉了整个应用进程。
2. 进程仍在，但 Kotlin 前台服务被系统重建，而 Rust/Tauri 运行时没有随之恢复。
3. Wi-Fi/移动网络切换或上游 NAT 空闲超时，导致服务端侧已有连接消失。

区分方法见“Android 后台运行与睡眠”和“设备诊断”章节。

## 5. Android 后台运行与睡眠

应用使用非 VPN 的 `specialUse` 前台服务维持本地 SOCKS5，主要配置包括：

- `android:stopWithTask="false"`：从最近任务划掉应用不会主动停止服务。
- `START_STICKY`：进程被系统终止后允许 Android 重建 Kotlin 前台服务。
- `PARTIAL_WAKE_LOCK`：降低睡眠时 CPU 被挂起的概率。
- `WIFI_MODE_FULL_HIGH_PERF` Wi-Fi Lock：降低睡眠时 Wi-Fi 被关闭的概率。
- 通知渠道和电池优化豁免入口。

这些措施不能绕过小米、华为、OPPO、vivo 等设备的厂商省电策略。需要允许应用自启动、后台运行，并关闭针对本应用的电池优化限制。

关键限制：

- `START_STICKY` 只能让 Android 重建 Kotlin 前台服务，不能重新创建 Rust/Tauri 运行时。
- 当前自动恢复逻辑会在应用下次启动或回到前台时，根据 `resume.intent` 检测上次运行状态并尝试重启本地 SOCKS5。
- 如果整个进程已被厂商杀掉，必须重新打开应用，或在系统后台策略中彻底放行应用。
- 前台服务状态、WakeLock、Wi-Fi Lock 可能因系统重建而变化，界面会显示当前状态和 `foregroundServiceError`。

## 6. 日志和日志上限

实现位置：

```text
E:\project\rust\rama_proxy\proxy-mobile\src-tauri\src\lib.rs
E:\project\rust\rama_proxy\proxy-mobile\src\routes\+page.svelte
```

当前限制：

- 内存日志缓冲区最多保留 `1,000` 行。
- 界面只显示最近 `300` 行，按最新日志在前显示。
- 界面日志默认每 `2` 秒自动刷新。
- 当前日志文件：`<app_data_dir>/rama-proxy.log`。
- 文件达到 `2 MiB` 后轮转为 `rama-proxy.log.1`。
- 下一次轮转时删除旧的 `.1` 后再创建新的 `.1`。
- 磁盘上最多保留当前文件和一份轮转文件，总占用约不超过 `4 MiB`。
- 清空日志会同时清空内存缓冲、截断当前日志并删除 `rama-proxy.log.1`。
- 重启后只从当前 `rama-proxy.log` 回读最近最多 `1,000` 条有效 JSON 记录；`.1` 不会自动回读，仍可用于人工排查。
- Android Logcat 标签为 `RamaProxy`。

查看 Logcat：

```powershell
$adb = 'D:\resp\android\platform-tools\adb.exe'
& $adb logcat -v time -s RamaProxy:I *:S
```

因此长时间运行不会让日志无限增长。需要长期审计时应另行增加外部日志采集，不能依赖移动端本地日志文件。

## 7. TLS 和 CA 证书

Android Release 默认禁止明文流量，正式环境应启用 TLS。启用 TLS 后：

1. 在界面中点击“选择 PEM 证书”。
2. 通过 Android Storage Access Framework（SAF）选择 `.pem`、`.crt` 或 `.cer` 文件。
3. 应用校验内容必须是 PEM，并复制到应用私有目录：

   ```text
   <app_data_dir>/certs/ca.pem
   ```

4. 保存配置后再启动本地 SOCKS5。

注意事项：

- 仅支持 PEM 文本证书，不支持 DER 二进制证书。
- 一个 PEM 文件可以包含一张或多张 CA 证书。
- CA 文件最大 `512 KiB`。
- 不需要申请外部存储权限，用户通过系统文件选择器授权读取。
- 证书目录权限设置为 `0700`，证书文件权限设置为 `0600`（Unix/Android）。
- 重新选择证书会覆盖受管 `ca.pem`。
- “移除”只删除应用私有目录中的受管证书并清空界面路径。
- 未选择 CA 时，启用 TLS 会阻止启动并提示先导入证书。
- 当前移动端只管理 CA 信任证书，不提供客户端证书/私钥导入；移动端会清空 `client_cert_path` 等字段。
- `tls.insecure_skip_verify` 是保留字段，开启 TLS 时会被拒绝，不要尝试用它绕过证书校验。

不要要求用户在手机文件管理器里手工填写证书路径；应使用应用内的文件选择流程。

## 8. Debug 与 Release 的区别

| 项目 | Debug | Release |
| --- | --- | --- |
| 包名 | `com.zqliang.ramaproxy.debug` | `com.zqliang.ramaproxy` |
| 明文 HTTP | 允许 | 默认禁止 |
| 可调试 | 是 | 否 |
| R8/minify | 否 | 是 |
| Rust 构建 | Debug | Cargo `--release` |
| 前端 | 生产静态文件 | 生产静态文件 |
| 签名 | Android Debug 签名 | 读取 `keystore.properties`，否则 unsigned |

注意：Gradle 的 Debug APK 也设置了 `TAURI_ENV_DEBUG=false` 并嵌入生产前端，不会访问 `localhost:1420`。

Debug 和 Release 包名不同，可以同时安装，但它们不是同一个应用，也不能互相覆盖升级。

## 9. Android 构建环境和命令

本机已验证环境：

- JDK 17：`D:\app\Java\jdk-17.0.12`
- Android SDK：`D:\resp\android`
- SDK Platform：36
- Build Tools：36.0.0
- NDK：`27.2.12479018`
- Node.js/npm
- Rust stable 及 Android targets

安装 Rust Android targets：

```powershell
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

设置环境变量：

```powershell
$env:JAVA_HOME = 'D:\app\Java\jdk-17.0.12'
$env:ANDROID_HOME = 'D:\resp\android'
$env:ANDROID_SDK_ROOT = 'D:\resp\android'
$env:NDK_HOME = 'D:\resp\android\ndk\27.2.12479018'
```

首次安装前端依赖：

```powershell
Set-Location 'E:\project\rust\rama_proxy\proxy-mobile'
npm install
```

在 Android Studio 中打开：

```text
E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android
```

常用命令行构建：

```powershell
Set-Location 'E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android'

# 全部 ABI Debug
.\gradlew.bat assembleDebug

# 全部 ABI Release
.\gradlew.bat assembleRelease

# 常用 arm64 Release
.\gradlew.bat assembleArm64Release
```

Gradle 构建会执行前端构建、Rust 动态库构建、NDK strip，并使用 16 KB 页对齐链接参数。Release 下 Cargo 使用 `--release`。

Release 产物目录：

```text
E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android\app\build\outputs\apk\arm64\release\
```

真机优先安装：

```text
app-arm64-release.apk
```

不要安装或分发：

```text
app-arm64-release-unsigned.apk
```

模拟器通常使用 `x86_64` 产物。`universal` 包含全部 ABI，体积明显更大。

## 10. Release 签名和安装失败

“该安装包未包含任何证书”表示安装包没有有效签名，不等于手机证书商店缺少证书。应检查是否误用了 `*-release-unsigned.apk` 或签名配置未生效。

当前本机签名配置：

- Keystore：`C:\Users\sy\.android\rama-proxy-release.jks`
- Key alias：`rama-proxy`
- Gradle 配置：`E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android\keystore.properties`
- 证书主体：`CN=Rama Proxy, OU=Mobile, O=zqliang, L=Shanghai, ST=Shanghai, C=CN`
- 密钥算法：RSA 4096
- 证书 SHA-256：`b8845c1581fd8588f7b56b07f955940bcdf32d196138d48dd1074b64bef0fd0d`

规则：

- 真机发布必须使用已签名 APK。
- Android 升级包必须使用与已安装版本相同的签名证书；证书不同会安装失败。
- 发布前备份 keystore 和 `keystore.properties`，但不得提交到仓库。
- 不要在聊天、文档、日志或命令输出中打印 keystore 密码。
- 如果 `keystore.properties` 不存在，Gradle 仍可能生成 unsigned 产物，但该文件不能用于升级或发布。
- 仓库只保存模板/忽略规则，不保存密钥和密码。

`keystore.properties`、`local.properties`、`*.jks`、`*.keystore` 必须保持本地私有。提交前运行：

```powershell
git check-ignore -v `
  proxy-mobile/src-tauri/gen/android/keystore.properties `
  proxy-mobile/src-tauri/gen/android/local.properties
```

## 11. APK 验证

检查包名、版本和权限：

```powershell
$apk = 'E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android\app\build\outputs\apk\arm64\release\app-arm64-release.apk'

& 'D:\resp\android\build-tools\36.0.0\aapt2.exe' dump badging $apk |
    Select-String 'package:|application-label:'

& 'D:\resp\android\build-tools\36.0.0\aapt2.exe' dump permissions $apk
```

Release 预期包含：

```text
android.permission.INTERNET
android.permission.ACCESS_WIFI_STATE
android.permission.FOREGROUND_SERVICE
android.permission.FOREGROUND_SERVICE_SPECIAL_USE
android.permission.POST_NOTIFICATIONS
android.permission.WAKE_LOCK
android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS
com.zqliang.ramaproxy.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION
```

不应包含：

```text
android.permission.BIND_VPN_SERVICE
```

检查 ABI：

```powershell
& 'D:\app\Java\jdk-17.0.12\bin\jar.exe' tf $apk |
    Select-String '^lib/.*/librama_proxy_mobile_lib\.so$'
```

arm64 Release 应只包含 `arm64-v8a` 的原生库。

检查签名：

```powershell
& 'D:\resp\android\build-tools\36.0.0\apksigner.bat' verify --verbose --print-certs $apk
```

预期至少包含：

```text
Verifies
Verified using v2 scheme (APK Signature Scheme v2): true
```

并确认证书 SHA-256 与上一节记录的签名证书一致。一次发布中所有渠道应使用同一证书。

检查 `arm64-v8a` 产物哈希：

```powershell
Get-FileHash -LiteralPath $apk -Algorithm SHA256
```

## 12. 16 KB 页兼容

链接参数已设置：

```text
-Clink-arg=-Wl,-z,max-page-size=16384
-Clink-arg=-Wl,-z,common-page-size=16384
```

检查所有 ABI 的 `LOAD` 段：

```powershell
$readelf = 'D:\resp\android\ndk\27.2.12479018\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe'
Set-Location 'E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android'
foreach ($abi in @('arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64')) {
    Write-Output "[$abi]"
    & $readelf -lW "app\src\main\jniLibs\$abi\librama_proxy_mobile_lib.so" |
        Select-String '^\s*LOAD'
}
```

四种 ABI 的所有 `LOAD` 段 `Align` 均应为 `0x4000`。这关系到 Android 16 KB 页设备兼容性。

## 13. 设备诊断

先确认设备已连接：

```powershell
$adb = 'D:\resp\android\platform-tools\adb.exe'
& $adb devices
```

查看进程和前台服务：

```powershell
& $adb shell pidof com.zqliang.ramaproxy
& $adb shell dumpsys activity services com.zqliang.ramaproxy
```

判断方式：

- 没有 PID：整个进程已被 Android 或厂商电源策略杀死，已有连接必然全部断开。
- 有 PID、没有前台服务：Kotlin 前台服务生命周期异常，结合 Logcat 排查。
- PID 和前台服务都在、连接池为 0：查看 `lastRefillError`、`consecutiveFailures`，通常是网络切换、TLS、证书或上游不可达。
- 连接池存在但服务端连接消失：检查 Wi-Fi/移动网络切换和上游 NAT 空闲超时；客户端会定期探测空闲隧道并补池。
- Kotlin 服务被 `START_STICKY` 重建但 SOCKS5 未恢复：Rust/Tauri 运行时不会由系统自动创建，重新打开应用触发恢复。

查看日志：

```powershell
& $adb logcat -v time -s RamaProxy:I *:S
```

验证本地 SOCKS5 握手（Debug 包）：

```powershell
& $adb install -r `
  'E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android\app\build\outputs\apk\x86_64\debug\app-x86_64-debug.apk'
& $adb forward tcp:11080 tcp:1080

$client = [System.Net.Sockets.TcpClient]::new()
$client.Connect('127.0.0.1', 11080)
$stream = $client.GetStream()
$request = [byte[]](0x05, 0x01, 0x00)
$stream.Write($request, 0, $request.Length)
$stream.Flush()
$response = [byte[]]::new(2)
$count = $stream.Read($response, 0, 2)
($response[0..($count - 1)] | ForEach-Object { $_.ToString('X2') }) -join ' '

$stream.Dispose()
$client.Dispose()
& $adb forward --remove tcp:11080
```

预期输出 `05 00`，表示 SOCKS5 无认证协商成功。

## 14. 测试和构建检查

在仓库根目录运行：

```powershell
Set-Location 'E:\project\rust\rama_proxy'
cargo fmt --all -- --check
cargo test -p proxy-core --test udp_associate -- --nocapture
cargo test -p proxy-core
cargo check -p proxy-core -p rama-proxy-mobile
```

在移动端目录运行：

```powershell
Set-Location 'E:\project\rust\rama_proxy\proxy-mobile'
npm run check
npm run build
```

UDP 测试会启动真实的 `proxy-core client`、`proxy-core server` 和本地 UDP echo server，覆盖 SOCKS5 握手、`UDP ASSOCIATE`、数据报封装、往返 payload 和源地址。第二个测试单独验证 TCP 池可以在 UDP 关闭时完成预热。

## 15. 版本同步和发布检查清单

Android 发布版本必须在以下文件中保持一致：

```text
E:\project\rust\rama_proxy\proxy-mobile\package.json
E:\project\rust\rama_proxy\proxy-mobile\src-tauri\Cargo.toml
E:\project\rust\rama_proxy\proxy-mobile\src-tauri\tauri.conf.json
E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android\app\tauri.properties
E:\project\rust\rama_proxy\proxy-mobile\package-lock.json
E:\project\rust\rama_proxy\Cargo.lock
```

同时检查：

- `versionName` 与发布版本一致。
- `versionCode` 单调递增，不能回退。
- `package-lock.json` 顶层和 `packages[""].version` 与 `package.json` 一致。
- `Cargo.lock` 中 `rama-proxy-mobile` 的版本与移动端 `Cargo.toml` 一致。
- 根 `Cargo.toml` 的 `workspace.package.version` 当前是 `1.4.0`；移动端 `Cargo.toml`、`tauri.conf.json`、`package.json` 和 `package-lock.json` 也必须保持 `1.4.0`。
- 不要提交 `local.properties`、`keystore.properties`、`*.jks`、`*.keystore` 或密码。
- Release APK 必须签名并通过 `apksigner verify`。
- 发布前用同一证书和更高 `versionCode` 构建升级包。
- 发布前检查 `BIND_VPN_SERVICE` 不存在。
- 发布前检查 arm64 原生库、16 KB 页对齐和 SHA-256。

v1.4.0 已将根 workspace、移动端 Rust/Tauri、`package.json` 和 `package-lock.json` 统一为 `1.4.0`，Android `versionCode` 为 `1400`。

## 16. 本次已验证记录

2026-11-08 的本地验证结果：

- `cargo fmt --all -- --check` 通过。
- `cargo check -p proxy-core -p rama-proxy-mobile` 通过。
- `cargo test -p proxy-core --test udp_associate -- --nocapture` 通过。
- `cargo test -p proxy-core` 通过。
- `npm run check` 通过。
- `npm run build` 通过。
- Gradle `assembleArm64Release` 成功，使用 Cargo release 构建；APK Signature Scheme v2 和 `zipalign -c -P 16` 验证通过。
- APK 版本：`1.4.0`，`versionCode`：`1400`。
- APK ABI：`arm64-v8a`。
- APK 大小：`12,368,467` 字节。
- APK SHA-256：`F977ED29F184A58B72E45ACFDB461B49A2434325A26342AA212246B3DCDA5D56`。
- 签名证书 SHA-256：`b8845c1581fd8588f7b56b07f955940bcdf32d196138d48dd1074b64bef0fd0d`。
- 曾在 Android 17（API 37、16 KB 页）的 `sdk_gphone16k_x86_64` 模拟器验证前端加载、本地监听 `127.0.0.1:1080`、SOCKS5 `05 00` 握手及四种 ABI 的 `0x4000` 对齐。
- 本次文档更新时没有连接 Android 真机；真机睡眠和厂商保活行为仍需在目标机型上验证。

## 17. 已知限制

- Android 端不提供 VPN/VpnService，不能自动接管全系统流量。
- SOCKS5 无认证，不要直接暴露到局域网或公网。
- UDP 依赖上游 server 的 UDP relay，且不支持 SOCKS5 UDP 分片。
- TLS 只支持 PEM CA 信任导入；移动端当前不支持客户端证书/私钥。
- Android 厂商省电策略可能杀掉进程；前台服务、WakeLock 和 Wi-Fi Lock 不能保证进程永不被杀。
- `START_STICKY` 不会自动恢复 Rust/Tauri 运行时，需要用户重新打开应用触发恢复。
- 日志采用有界内存和有界磁盘轮转，不适合作为长期审计存储。
- Release 使用 R8/minify；如果新增依赖依赖反射或 JNI 命名，需要同步检查 ProGuard 规则。
- Release 升级必须保持签名证书不变；丢失 keystore 后不能覆盖升级已有安装。
- 移动端 Release 禁止明文流量，测试上游明文服务应使用 Debug 包或正确配置 TLS。
- 模拟器验证不能替代目标真机的厂商后台策略、网络切换和长时间睡眠测试。

## 18. 文档维护要求

出现以下变更时，必须同步更新本文和 `proxy-mobile/README.md`：

- 日志保留行数、文件大小、轮转策略或 Logcat 标签变化。
- UDP 支持范围、分片策略或上游协议变化。
- TCP 池预热、心跳、补池或诊断字段变化。
- Android 前台服务、WakeLock、电池优化或自动恢复逻辑变化。
- TLS 证书格式、路径、大小限制或客户端证书支持变化。
- 包名、版本号、签名配置、ABI、SDK/NDK 或构建命令变化。
- 新增会被用户误判为故障的行为。