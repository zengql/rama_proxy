# rama-proxy v1.3.0 发布说明

- 发布日期：2026-11-07
- 版本：v1.3.0（上一版本 v1.2.2）
- 分支：`1.3.0` → 合并到 `main`
- 平台：Windows 桌面客户端（GUI）+ Linux/Windows 服务端与客户端 CLI

## 发布概览

v1.3.0 在 v1.2.2 基础上增加了 Windows 桌面客户端 `proxy-gui.exe`，并把原本计划在 1.2.3
的守护进程、Web UI 管理能力一并纳入本版本。核心代理功能（SOCKS5 TCP/UDP、隧道池、
TLS）保持向后兼容，配置文件无需迁移。

## 新增功能

### 桌面客户端（`proxy-gui.exe`，Windows）

- 单窗口管理完整的客户端生命周期：双击启动后自动拉起同目录的 `proxy-core.exe`，
  Enable / Disable 控制代理启停。
- 设置面板覆盖 Tunnel、Local listeners、Authentication、TLS、Logging、Application
  六组配置，保存后写入 `config/client.toml`。
- 托盘图标（`Open` / `Exit`），关闭按钮行为可选：`Ask`（弹确认框，默认）、
  `Exit`（直接退出）、`Close to tray`（收起到托盘）。
- 内置控制台输出视图，支持 `Follow latest` 自动跟随最新日志；手动滚动控制台后
  会自动关闭跟随，避免打断历史日志查看。
- `gpui-kit` 升级到 `0.8` 并启用 `gpui-fast` 渲染特性。

### 命令行与 Web UI

- 新增顶层 `rama-proxy stop`，一次停止后台运行的 server、client 和 ui 进程。
- 新增 `ui stop` 与 `ui --daemon`，用于管理内置 Web UI 进程。
- 新增 `ui init`，生成包含 bind 地址、端口、PID 文件、stats socket、采样间隔的
  `config/ui.toml`。
- UI 默认从 `config/ui.toml` 读取配置，命令行参数可覆盖配置文件。

## 修复

- 修复托盘图标资源加载失败问题：Windows 资源编译器保留了 RC 标识符的引号，
  托盘图标改按带引号的资源名加载。
- 修复托盘失效后无法恢复窗口的问题：启动时校验托盘是否可用，并在托盘图标丢失
  （例如 Windows Explorer 重启）后每 60 秒自动重建托盘与菜单。
- 修复关闭到托盘实际只是最小化的问题：`Close to tray` 现在真正隐藏窗口，
  由托盘 `Open` 恢复；托盘不可用时保持窗口打开并在界面提示，避免程序"看似关不掉"。
- 修复托盘命令通道断开后监听任务空转的问题（区分 `Empty` 与 `Disconnected`）。
- 修复 Web UI 在 stats socket 短暂失败时丢失客户端名称与隧道数据的问题，改为保留
  上一次成功快照。
- 修复心跳隧道被旧的 600 秒时间过滤误删的问题，活跃隧道不再被错误移除。
- 修复默认客户端 ID 的推导逻辑。

## 升级说明

- `Cargo.toml` 不再对 `gpui-pre-http-client-tls` 打 patch，改为使用 `gpui-kit 0.8`
  的默认依赖链。
- 现有 `config/client.toml`、`config/server.toml` 可直接沿用，不需要手工迁移。
- 关闭行为的历史配置 `MinimizeToTray` 保留原枚举值，界面文案改为 `Close to tray`，
  语义为隐藏到托盘。

## 发布包内容

`dist/rama-proxy-v1.3.0/`：

```text
proxy-gui.exe    界面程序（双击运行），自动拉起同目录的 proxy-core.exe
proxy-core.exe   核心程序（客户端 CLI / 服务端 CLI / Web UI）
config/          client.toml、server.toml 配置模板
README.txt       面向使用者的中文使用说明
```

## 已知限制

- GUI 目前只提供 Windows 构建，托盘依赖 Windows Explorer。
- TLS 证书仅支持 PEM（`.crt` / `.pem` / `.key`），不支持 p12 / jks。
- `tls.insecure_skip_verify` 为保留字段，开启 TLS 时校验会拒绝该项。
- `rama` 仍固定在 vendored `0.3.0-alpha.4`；`0.4.0` 包含破坏性 API 变更，未纳入本版本。
