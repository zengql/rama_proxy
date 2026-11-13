# Rama Proxy

Rama Proxy 是一个基于 Rust 的代理项目，包含桌面端、核心 CLI/服务端和 Android 移动端。Android 客户端复用 `proxy-core`，使用 Tauri 2 + SvelteKit 构建。

> `proxy-gui` 是 GPUI 桌面项目，不是 Tauri；Android 工程位于 `proxy-mobile`。

## 组件

| 路径 | 用途 | 平台/技术 |
| --- | --- | --- |
| `proxy-core` | 代理核心、SOCKS5 客户端/服务端、UDP relay、TLS、隧道池、CLI、Web UI | Rust |
| `proxy-gui` | 桌面 GUI，负责拉起和管理同目录的 `proxy-core` | Windows / GPUI |
| `proxy-mobile` | Android 本地 SOCKS5 客户端 | Tauri 2 + SvelteKit + Rust |

## 先读

- [项目注意事项与运维手册](docs/PROJECT-NOTES.md)：构建、签名、UDP、TCP 连接池、日志、TLS、Android 睡眠和诊断。
- [Android 客户端详细说明](proxy-mobile/README.md)：Android Studio 导入、ABI、APK 产物和端到端验证命令。
- [v1.4.2 发布说明](RELEASE-NOTES-1.4.2.md)：Android 前台服务被系统重建后自动恢复 Rust SOCKS5，修复本地 1080 端口消失导致其他代理前端断流。
- [v1.4.1 发布说明](RELEASE-NOTES-1.4.1.md)：Android 按流量持有 WakeLock/Wi-Fi Lock，修复睡眠后复用失效隧道和心跳反复重连。
- [v1.4.0 发布说明](RELEASE-NOTES-1.4.0.md)：Android 客户端、TLS CA 导入、TCP 池诊断、UDP ASSOCIATE、后台运行和日志上限。
- [v1.3.0 发布说明](RELEASE-NOTES-1.3.0.md)：桌面端和 CLI 的历史发布变更。

## 最重要的边界

- Android 客户端**只提供本地 SOCKS5 端口**，不实现 VPN/VpnService，也不接管系统全局流量；需要代理的应用必须手动填写 `127.0.0.1:<端口>`。
- Android 前台服务被 `START_STICKY` 重建时会通过 JNI 自动恢复 Rust SOCKS5；若系统彻底杀掉进程、强制停止或禁止服务重建，仍需厂商保活或手动打开应用。
- Android 的 TCP 连接池与 `UDP ASSOCIATE` 相互独立。开启 UDP 不是连接池预热的前提。
- TLS 启用前必须先在移动端导入 PEM CA 证书；移动端当前只管理 CA，不提供客户端证书/私钥导入。
- Release 真机安装必须使用已签名 APK。出现“该安装包未包含任何证书”时，说明安装的是未签名产物，不能用它发布。
- 升级包必须使用与已安装版本相同的签名证书。发布前需备份 keystore 和 `keystore.properties`。
- 日志不是无限增长：内存 1,000 行、界面最近 300 行、日志文件按 2 MiB 轮转，磁盘最多保留两个文件。

## Android 快速构建

先设置本机已验证的构建环境：

```powershell
$env:JAVA_HOME = 'D:\app\Java\jdk-17.0.12'
$env:ANDROID_HOME = 'D:\resp\android'
$env:ANDROID_SDK_ROOT = 'D:\resp\android'
$env:NDK_HOME = 'D:\resp\android\ndk\27.2.12479018'
```

构建 arm64 Release 包：

```powershell
Set-Location 'E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android'
.\gradlew.bat assembleArm64Release
```

签名 APK 输出路径：

```text
E:\project\rust\rama_proxy\proxy-mobile\src-tauri\gen\android\app\build\outputs\apk\arm64\release\app-arm64-release.apk
```

不要分发 `app-arm64-release-unsigned.apk`。完整验证和故障判断见 [项目注意事项](docs/PROJECT-NOTES.md)。