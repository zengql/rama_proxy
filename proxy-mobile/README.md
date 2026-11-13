# Rama Proxy Mobile

`proxy-mobile` 是基于 **Tauri 2 + SvelteKit + Rust** 的 Android 客户端，复用仓库内的 `proxy-core`。

它只在本机提供 SOCKS5 端口，不实现 VPN/VpnService，也不会接管 Android 全局流量。需要使用代理的应用必须手动填写本地 SOCKS5 地址。

> 原 `proxy-gui` 使用 GPUI，并包含 Windows 窗口/托盘实现，不是 Tauri，不能直接作为 Android 工程构建。因此 Android 入口放在本目录，仅复用 `proxy-core`。

> 跨模块的构建、签名、日志上限、UDP/TCP 池和睡眠诊断总览见 [项目注意事项与运维手册](../docs/PROJECT-NOTES.md)。

## 功能边界

- 本地监听地址固定为 `127.0.0.1`。
- 默认 SOCKS5 端口为 `1080`，可在界面中修改。
- SOCKS5 固定为无认证模式。
- 支持 SOCKS5 `CONNECT`（TCP）和 `UDP ASSOCIATE`（UDP）。
- UDP 默认关闭，需要在“高级选项”中手动开启。
- UDP relay 监听 `127.0.0.1` 上的临时端口，不对外网卡暴露。
- 支持 SOCKS5 UDP 数据报封装，但不支持 UDP 分片；`FRAG != 0` 的数据报会被拒绝。
- 上游 Rama server 必须同时支持 UDP relay。
- 固定关闭 HTTP CONNECT 监听。
- 不申请 `BIND_VPN_SERVICE` 权限，不包含 `VpnService`。
- 不实现系统级代理、透明代理或流量接管。

## 目录

```text
proxy-mobile/
├─ src/                         # SvelteKit 界面
├─ src-tauri/
│  ├─ src/lib.rs                # Tauri 命令与 SOCKS5 生命周期
│  ├─ tauri.conf.json
│  └─ gen/android/              # 可直接用 Android Studio 打开的工程
├─ package.json
└─ README.md
```

## 环境要求

已在本机验证的构建环境：

- JDK 17：`D:\app\Java\jdk-17.0.12`
- Android SDK：`D:\resp\android`
- Android SDK Platform：36
- Android Build Tools：36.0.0
- Android NDK：`27.2.12479018`
- Node.js/npm
- Rust stable，以及 Android targets：

```powershell
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

建议在命令行构建前设置：

```powershell
$env:JAVA_HOME = 'D:\app\Java\jdk-17.0.12'
$env:ANDROID_HOME = 'D:\resp\android'
$env:ANDROID_SDK_ROOT = 'D:\resp\android'
$env:NDK_HOME = 'D:\resp\android\ndk\27.2.12479018'
```

如果 Android Studio 未自动识别 SDK，可在 `src-tauri/gen/android/local.properties` 中配置：

```properties
sdk.dir=D\:\\resp\\android
```

`local.properties` 是机器本地文件，不应提交。

## 使用 Android Studio

1. 用 Android Studio 打开：

   ```text
   E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android
   ```

2. 等待 Gradle Sync 完成。
3. 选择 `app` 配置和连接的 Android 设备/模拟器。
4. 选择 `debug` 或 `release` Build Variant 后运行或构建。

Android 工程已经改为由 Gradle 原生任务构建 Rust 动态库，不再依赖 Tauri CLI 创建 `.so` 符号链接，因此不要求 Windows 开启开发者模式。

Gradle 构建任务会：

- 执行 `npm run build` 生成前端静态文件。
- 使用 `custom-protocol` 构建 Rust/Tauri 动态库。
- 设置 `TAURI_ENV_DEBUG=false`，因此 Debug APK 也嵌入生产前端，不会访问 `localhost:1420`。
- 使用 NDK `llvm-strip --strip-unneeded` 去除 APK 内原生库的调试符号。
- 使用 16 KB 页对齐链接参数，见下文。

Android Studio 的 Debug/Release 构建直接使用已经生成并纳入工程的 `gen/android`，不依赖 Tauri CLI 初始化。

## 包名

| 构建类型 | 包名 |
| --- | --- |
| Debug | `com.zqliang.ramaproxy.debug` |
| Release | `com.zqliang.ramaproxy` |

两种构建的应用显示名均为 `Rama Proxy`。

## 命令行构建

首次安装前端依赖：

```powershell
Set-Location 'E:\project\rust\rama_proxy\proxy-mobile'
npm install
```

构建全部 ABI 的 Debug APK：

```powershell
Set-Location 'E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android'
.\gradlew.bat assembleDebug
```

构建全部 ABI 的 Release APK：

```powershell
Set-Location 'E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android'
.\gradlew.bat assembleRelease
```

只构建常用的 arm64 Release 包：

```powershell
.\gradlew.bat assembleArm64Release
```

Gradle 的 Rust 构建任务在 Release 下使用 Cargo `--release`。

### Debug 产物

输出目录：

```text
src-tauri/gen/android/app/build/outputs/apk/
├─ arm64/debug/app-arm64-debug.apk
├─ arm/debug/app-arm-debug.apk
├─ x86/debug/app-x86-debug.apk
├─ x86_64/debug/app-x86_64-debug.apk
└─ universal/debug/app-universal-debug.apk
```

当前 Debug 构建产物大小约为：

```text
arm64       23.29 MB
armeabi-v7a 15.99 MB
x86         25.92 MB
x86_64      25.90 MB
universal   70.64 MB
```

### Release 产物

输出目录：

```text
src-tauri/gen/android/app/build/outputs/apk/
├─ arm64/release/app-arm64-release.apk
├─ arm/release/app-arm-release.apk
├─ x86/release/app-x86-release.apk
├─ x86_64/release/app-x86_64-release.apk
└─ universal/release/app-universal-release.apk
```

历史多 ABI Release 构建产物大小参考（不是 v1.4.0 全量构建记录）：

```text
arm64       10.29 MB
armeabi-v7a  7.51 MB
x86         11.44 MB
x86_64      11.09 MB
universal   32.87 MB
```

Release 构建启用了 R8/minify，并读取本机 `keystore.properties` 进行签名。真机安装请使用 `app-arm64-release.apk`，不要使用 `app-arm64-release-unsigned.apk`。

v1.4.0 已重新执行 arm64 Release 构建并验证：

```text
包名：com.zqliang.ramaproxy
versionName：1.4.0
versionCode：1400
ABI：arm64-v8a
大小：12,368,467 字节
SHA-256：F977ED29F184A58B72E45ACFDB461B49A2434325A26342AA212246B3DCDA5D56
签名证书 SHA-256：b8845c1581fd8588f7b56b07f955940bcdf32d196138d48dd1074b64bef0fd0d
签名方案：APK Signature Scheme v2 验证通过
16 KB 页对齐：zipalign -c -P 16 验证通过
```

当前本机 Release 签名配置：

- 证书：`CN=Rama Proxy, OU=Mobile, O=zqliang, L=Shanghai, ST=Shanghai, C=CN`
- 密钥算法：RSA 4096
- Keystore：`C:\Users\sy\.android\rama-proxy-release.jks`
- Key alias：`rama-proxy`
- Gradle 配置：`src-tauri/gen/android/keystore.properties`
- `keystore.properties` 和 `*.jks` 均已被 Git 忽略，不会进入仓库

使用同一签名密钥构建的 Release APK 可以直接安装。由于 Android 要求升级包使用相同证书，发布前必须备份 keystore 和 `keystore.properties`；丢失后无法覆盖升级已有安装。

如果 `keystore.properties` 不存在，Gradle 仍可构建，但产物会是未签名的 `*-release-unsigned.apk`。仓库不保存密钥和密码。

`universal` 包含全部四种 ABI，因此体积明显更大。日常真机安装优先使用 `arm64`，模拟器通常使用 `x86_64`。

## UDP ASSOCIATE

UDP 在界面的“高级选项”中配置：

- `UDP ASSOCIATE` 默认关闭。
- 只使用 TCP 代理时无需开启。
- 开启后，SOCKS5 客户端可对本地 `127.0.0.1:<SOCKS5 端口>` 发起 `UDP ASSOCIATE`。
- relay 地址由客户端返回，通常为 `127.0.0.1` 上的临时 UDP 端口。
- 客户端和 relay 只接受来自控制连接同一来源 IP 的 UDP 数据报。
- 不支持 SOCKS5 UDP 分片，分片数据报会失败。
- 服务端需开启 UDP tunnel 支持，端到端 UDP 才能工作。

## 16 KB 页兼容

链接时已设置：

```text
-Clink-arg=-Wl,-z,max-page-size=16384
-Clink-arg=-Wl,-z,common-page-size=16384
```

构建后可用 `llvm-readelf` 检查：

```powershell
$readelf = 'D:\resp\android\ndk\27.2.12479018\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe'
Set-Location 'E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android'
foreach ($abi in @('arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64')) {
    Write-Output "[$abi]"
    & $readelf -lW "app\src\main\jniLibs\$abi\librama_proxy_mobile_lib.so" |
        Select-String '^\s*LOAD'
}
```

四种 ABI 的所有 `LOAD` 段 `Align` 均应为 `0x4000`。

## 依赖说明

`rama` 固定使用 crates.io 的 `0.3.0-alpha.4`，与原先被 `.gitignore` 忽略的本地 `vendor` 源码逐文件一致。根 `Cargo.toml` 不再依赖该本地 `vendor` 目录，因此干净检出后可以直接构建。

`proxy-core` 的 TLS 改为显式依赖 `rustls` + `tokio-rustls` 的 ring backend，不再需要 `rama-tls-rustls` 的本地 patch。

## 配置说明

界面中的 `serverAddr` 是上游 Rama 服务地址，不是本地监听地址。本地监听地址始终为 `127.0.0.1:<socks5Port>`。

应用会将配置保存到 Tauri 的应用配置目录中的 `client.toml`。

Android Release 默认不允许明文流量，因此上游连接应启用 TLS；Debug 构建允许明文，便于本地联调。推荐在正式环境中使用 TLS，并在需要时配置自定义 CA。

## TLS 与 CA 证书

Android Release 默认禁止明文流量，因此在正式环境中应启用 TLS。启用 TLS 后：

1. 在界面中点击“选择 PEM 证书”。
2. 通过 Android 系统文件选择器选择 `.pem`、`.crt` 或 `.cer` 文件。
3. 应用会校验文件内容必须是 PEM，并将证书复制到应用私有目录：

   ```text
   <app_data_dir>/certs/ca.pem
   ```

4. 点击“保存配置”后再启动本地 SOCKS5。

说明：

- 仅支持 PEM 文本证书，不支持 DER 二进制证书。
- 一个 PEM 文件可以包含一张或多张 CA 证书。
- 无需手动填写手机上的证书路径，也不需要申请外部存储权限；文件选择由 Android Storage Access Framework（SAF）完成。
- 重新选择证书会覆盖应用私有目录中的 `ca.pem`；“移除”只会删除该受管文件并清空界面中的证书路径。
- 未选择 CA 证书时，启用 TLS 将阻止启动并提示先导入证书。

## 运行日志与诊断

应用界面的“诊断日志”会显示最近 300 条（内存缓冲保留最近 1,000 条）Rust 运行日志，默认每 2 秒刷新，也可以复制或清空。清空会同时清空内存、截断当前日志文件并删除轮转文件。日志同时写入应用私有目录：

```text
<app_data_dir>/rama-proxy.log
```

文件达到 2 MiB 后会轮转为 `rama-proxy.log.1`；下一次轮转会删除旧的 `.1`。磁盘最多保留当前文件和一份轮转文件，总占用约不超过 4 MiB。应用重启后只从当前日志回读最近最多 1,000 条记录，`.1` 需人工查看。Android 上还可以用 `adb logcat` 过滤 Kotlin 前台服务和 Rust 日志：

```powershell
$adb = 'D:\resp\android\platform-tools\adb.exe'
& $adb logcat -v time -s RamaProxy:I *:S
```

TCP 连接池与 `UDP ASSOCIATE` 相互独立。即使 UDP 关闭，启动 SOCKS5 后也应出现以下日志并预热到 `poolSize` 的连接：

```text
warm tunnel pool below target; scheduling refill
starting idle tunnel creation
fresh tunnel connection is ready
idle tunnel added to pool
heartbeat tunnel snapshot received
```

如果只看到心跳连接，应在界面中检查连接池的 `idle`、`connecting`、`consecutiveFailures`、`lastRefillError` 和 `lastSuccessAgeSecs`，并搜索日志中的：

```text
failed to create idle tunnel; refill will back off
failed to create fresh tunnel during acquire fallback
tunnel handshake failed
tls connect failed
```

开启 UDP 后连接池出现，不代表 UDP 是 TCP 连接池的前提；更可能是这次操作触发了保存/重启，使之前未成功的预热重新执行。应以客户端连接池状态和服务端 `heartbeat tunnel snapshot sent` 中的 `tunnel_count` 为准。

## 后台运行与睡眠

应用使用非 VPN 的 `specialUse` 前台服务维持本地 SOCKS5，不申请 `BIND_VPN_SERVICE`。服务配置包括：

- `android:stopWithTask="false"`，从最近任务中划掉应用时不会主动停止服务。
- `START_STICKY`，进程被系统终止后允许 Android 重新创建 Kotlin 前台服务；当服务收到空 `intent` 时，会加载 native 库并通过 JNI 自动恢复 Rust SOCKS5。
- 自动恢复读取应用数据目录中的 `resume.intent`、`client.toml` 和 `rama-proxy.log`。恢复期间界面显示“恢复中”，失败时通过 `restoreError` 显示原因。
- Tauri 启动与 JNI 恢复共享同一份 Rust runtime 状态，并串行执行，避免重复绑定本地端口。
- `PARTIAL_WAKE_LOCK` 与 `WIFI_MODE_FULL_HIGH_PERF` Wi-Fi Lock **按流量持有**：有代理连接时申请，连接全部结束 30 秒后释放；空闲时允许手机睡眠，避免系统提示“阻止睡眠 / 耗电异常”。经代理的长连接不断开时锁会一直持有。
- 通知渠道和电池优化豁免入口。必须加入电池优化白名单，否则 Doze 下后台网络会被切断。
- 睡眠后首个请求会先探测空闲隧道，失效则重建，可能多一些延迟。

界面中 `WakeLock 未持有` 在空闲时属于正常状态。细节见 [项目注意事项与运维手册](../docs/PROJECT-NOTES.md) 第 5 节。

恢复相关状态：

- `systemRestarted`：当前前台服务是否为 Android 在无 `intent` 情况下重建。
- `restoreInProgress`：Rust SOCKS5 自动恢复是否正在进行。
- `restoreError`：自动恢复失败原因；此时打开应用或回到前台仍会触发兜底恢复。
- `foregroundServiceRestoring`：前端用于避免与 Service 自动恢复竞争恢复任务。

这些措施不能绕过设备厂商的省电策略。小米、华为、OPPO、vivo 等系统仍可能杀掉进程；还需要在系统设置中允许自启动、后台运行，并关闭针对本应用的电池优化限制。

睡眠后连接全部消失时，按以下顺序判断：

```powershell
$adb = 'D:\resp\android\platform-tools\adb.exe'
& $adb shell pidof com.zqliang.ramaproxy
& $adb shell dumpsys activity services com.zqliang.ramaproxy
```

- 没有 PID：进程已被 Android 或厂商电源策略杀死，已有 TCP 连接必然全部断开。
- 有 PID、没有前台服务：前台服务生命周期异常，需要结合 logcat 检查。
- PID 和前台服务都在、连接池为 0：查看 `lastRefillError` 和 `consecutiveFailures`，通常是网络切换、TLS 或上游不可达。
- 连接池存在但服务端连接消失：检查移动网络/Wi-Fi 切换，以及上游 NAT 的空闲超时；客户端会定期探测空闲隧道并补池。

`START_STICKY` 重建前台服务时，Service 会在 `intent == null` 的情况下通过 JNI 自动恢复 Rust SOCKS5；自动恢复期间界面显示“恢复中”，失败时显示 `restoreError`。打开应用或回到前台仍会基于 `resume.intent` 做兜底恢复。若系统强制停止应用、彻底禁止服务重建或厂商持续杀进程，仍需在系统后台策略中放行应用，或手动打开应用恢复代理。

对应日志关键字：`foreground service restarted by Android without an intent; scheduling Rust runtime restore`、`restoring local SOCKS5 runtime from Android foreground service`、`Android runtime restored from foreground service`、`Android runtime restore failed`。

## 验证

前端与 Rust 检查：

```powershell
Set-Location 'E:\project\rust\rama_proxy'
cargo check -p proxy-core -p rama-proxy-mobile

Set-Location 'E:\project\rust\rama_proxy\proxy-mobile'
npm run check
npm run build
```

UDP ASSOCIATE 端到端测试会启动真实的 `proxy-core client`、`proxy-core server` 和本地 UDP echo server，验证 SOCKS5 握手、UDP ASSOCIATE、数据报封装、往返 payload 和源地址：

```powershell
Set-Location 'E:\project\rust\rama_proxy'
cargo test -p proxy-core --test udp_associate -- --nocapture
```

运行 `proxy-core` 全部测试：

```powershell
cargo test -p proxy-core
```

检查 Release APK 包名、应用名和权限：

```powershell
$apk = 'E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android\app\build\outputs\apk\arm64\release\app-arm64-release.apk'

& 'D:\resp\android\build-tools\36.0.0\aapt2.exe' dump badging $apk |
    Select-String 'package:|application-label:'

& 'D:\resp\android\build-tools\36.0.0\aapt2.exe' dump permissions $apk
```

Release 预期包名为 `com.zqliang.ramaproxy`，业务权限包含：

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

不应出现 `BIND_VPN_SERVICE`。

检查原生库 ABI：

```powershell
& 'D:\app\Java\jdk-17.0.12\bin\jar.exe' tf `
  'E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android\app\build\outputs\apk\arm64\release\app-arm64-release.apk' |
  Select-String '^lib/.*/librama_proxy_mobile_lib\.so$'
```

arm64 Release 包应包含 `arm64-v8a`。

检查 Release 签名状态：

```powershell
& 'D:\resp\android\build-tools\36.0.0\apksigner.bat' verify --verbose `
  'E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android\app\build\outputs\apk\arm64\release\app-arm64-release.apk'
```

预期输出包含 `Verifies` 和至少一个 `Verified using v2 scheme (APK Signature Scheme v2): true`。当前签名证书的 SHA-256 摘要为：

```text
b8845c1581fd8588f7b56b07f955940bcdf32d196138d48dd1074b64bef0fd0d
```

检查本地 SOCKS5 握手（Debug 包）：

```powershell
$adb = 'D:\resp\android\platform-tools\adb.exe'
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

预期输出 `05 00`，表示 SOCKS5 no-auth 握手成功。

已在 Android 17（API 37、16 KB 页大小）的 `sdk_gphone16k_x86_64` 模拟器验证：

- 前端正常加载，无 `localhost:1420` 错误。
- 应用启动后监听 `127.0.0.1:1080`。
- SOCKS5 握手返回 `05 00`。
- 四种 ABI 的 `LOAD` 段均为 `0x4000` 对齐。
- 应用进程无 FATAL/JNI 崩溃。
- UDP ASSOCIATE 已通过真实 client/server/echo 端到端测试。