# rama-proxy v1.5.0 发布说明

- 发布日期：2026-11-28
- 版本：v1.5.0（上一版本 v1.4.2）
- 发布分支：`1.5.0`（基于 `1.4.2`）
- 适用组件：`proxy-core`、`proxy-gui`、`proxy-mobile`（客户端及移动端隧道协议保持兼容）

## 发布概览

v1.5.0 包含以下核心改进：

1. **服务端可选 SOCKS5 上游中继模式**：当服务端配置 `[upstream]` 后，所有数据面流量（TCP 与 UDP）统一经上游 SOCKS5 代理转发，当前服务端主机仅作为中继节点；不本地解析目标域名，也不在上游不可用或拒绝请求时回退直连。未配置 `[upstream]` 时，保持原有直连出站行为完全不变。
2. **修复 Windows 桌面端 `proxy-gui` 托盘事件线程空转高占用 CPU**：排查发现三方库 `tray-item 0.10.0` 的 Windows `event_loop` 线程在初始化失败退出时未处理 `RecvError`，导致孤立线程死循环空转吃满 1 个逻辑核（约 12.5%–13.0% 整机 CPU）。v1.5.0 在 Windows 平台移除 `tray-item` 依赖，替换为自研无自旋单线程原生 Win32 托盘实现。
3. **`proxy-gui` 真·无窗口简化模式与托盘右键启停**：核心进程状态从窗口视图拆离，简化模式启动时不创建主窗口、收起到托盘直接销毁窗口以释放 GPUI 窗口与 GPU 渲染资源，点击托盘 `Open` 时按需重建窗口；托盘右键菜单支持直接启停 `proxy-core`。
4. **客户端核心按需唤醒与两阶段空闲休眠（假死模式）**：内置到 `proxy-core`（无新增配置项，移动端、桌面端 GUI、CLI 通用）：启动后仅监听本地端口、不建预留隧道也不发心跳；收到本地请求时立即唤醒并复用/新建隧道、补足预留池并开启心跳；连续空闲 5 分钟后关闭预留隧道仅保留心跳；再空闲 5 分钟后断开心跳并挂起全部后台定时器进入休眠，每次请求均会重置空闲计时器。

## 核心变更

### 1. `[upstream]` 配置与校验

- 在服务端配置 [config.rs](proxy-core/src/config.rs) 新增可选字段 `upstream`（`UpstreamSocks5Config`），使用 `#[serde(deny_unknown_fields)]` 严格校验配置字段：
  - `address`：上游 SOCKS5 地址（`HostWithPort`），端口必须大于 `0`。
  - `username` / `password`：可选用户名与密码，必须成对省略或同时提供（长度均为 `1..=255` 字节）。
  - `connect_timeout_secs`：可选建连及上游握手超时（秒），默认 `10` 秒，配置时必须大于 `0`。
- `rama-proxy server init` 生成的默认模板中新增 `[upstream]` 注释示例。
- `rama-proxy server check` 输出中新增 `upstream=...` 摘要（未配置时显示 `direct`）。

### 2. TCP 与 UDP 全量经上游中继（无回退、无本地目标 DNS 解析）

- **TCP 隧道（SOCKS5 `CONNECT`）**：
  - 拨号目标切换为 `upstream.address`，仅解析上游地址本身；随后在 SOCKS5 握手阶段直接向 [upstream.rs](proxy-core/src/server_runtime/upstream.rs) 传入原始 `HostWithPort` 目标地址，由上游完成目标域名解析与建连。
  - 在 `tcp_connect` 成功后、SOCKS5 方法协商与认证之前即对上游套接字设置 `TCP_NODELAY` 和 `tcp_keepalive_secs`，减少小包握手延迟。
  - 建连超时在配置上游时默认使用 `10` 秒（可通过 `upstream.connect_timeout_secs` 调整），未配置上游时维持 `5` 秒直连超时。
- **UDP 隧道（SOCKS5 `UDP ASSOCIATE`）**：
  - 向 `upstream.address` 发起 `UDP ASSOCIATE` 请求（目标端点传 `0.0.0.0:0` / `[::]:0`，适配 NAT 后学习实际 UDP 源端），并对控制连接开启 `TCP_NODELAY` 与 TCP Keepalive，避免 NAT/防火墙静默回收空闲控制连接。
  - 若上游返回全零 IP 中继地址，自动回填上游对端 IP；上行 UDP 数据报封装 SOCKS5 UDP 头发往上游中继，下行解包后透传源地址与负载回客户端。
  - 持续监听上游 TCP 控制连接：正常关闭（EOF）、收到异常字节或 I/O 错误时分别记录日志并同步向客户端发送关闭帧结束会话。
  - 对 `recv_from` / `send` 遇到的瞬时单包错误（如 `ConnectionReset` / `ConnectionRefused` / `EMSGSIZE`）记录日志并丢弃当前包，避免单包异常中断整条 UDP 隧道。
- **严格无回退**：无论是连接上游失败、超时、认证方法不匹配、用户名密码认证被拒，还是 `CONNECT` / `UDP ASSOCIATE` 返回非成功状态，均直接向客户端回报错误并终止隧道，不会回退本地直连。

### 3. 修复 Windows 桌面端 `proxy-gui` 托盘线程空转高占用 CPU

- **根因**：`tray-item 0.10.0` 在 `TrayItemWindows::new` 中会先创建一条独立的 `event_loop` 线程，循环体写成 `if let Ok(v) = event_rx.recv() { ... }` 而未在 `Err(RecvError)` 时跳出；当 `init_window()` 初始化失败提前返回 `Err` 并丢弃 `Sender` 后，该后台线程会陷入无限死循环空转（`monitor_tray` 失败重试还会放大此问题）。同时其 `run_loop()` 未检查 `GetMessageW` 返回 `-1` 的错误分支，且 `TaskbarCreated` 重建图标硬编码资源名 `"tray-default"`。
- **修复方案**：在 [proxy-gui/src/tray.rs](proxy-gui/src/tray.rs) 为 Windows 平台实现原生单线程 Win32 托盘（[proxy-gui/Cargo.toml](proxy-gui/Cargo.toml) 仅在非 Windows 平台保留 `tray-item` 依赖）：
  - 移除独立 `event_loop` 转发线程，在托盘窗口过程 `WM_COMMAND` 中直接投递 `TrayCommand`。
  - 消息循环严格判断 `GetMessageW(&mut msg, 0, 0, 0) <= 0` 即退出，杜绝任何异常空转。
  - 初始化任一步失败时立即清理已分配句柄并返回错误，不遗留后台线程；支持响应 `TaskbarCreated` 自动重建托盘图标并在失败时标记不可用供 `monitor_tray` 正常恢复。

### 4. `proxy-gui` 托盘简化模式与右键启停控制

- **无窗口驻留与按需建窗释放渲染资源**：将代理子进程、配置表单与控制台日志缓存抽离至进程级 `AppState`，主窗口 `ClientView` 仅在界面显示时存在。
  - 启用 `Simplified mode (start windowless in tray)`（持久化字段 `simplified_mode`，或通过 `--tray` / `--simplified` 启动）后，启动时**不创建任何 GPUI 主窗口**，直接以纯托盘进程运行。
  - 窗口关闭选择“Close to tray”时直接销毁窗口实例，释放 GPUI 窗口句柄及 GPU/显存渲染表面资源，同时保持 `proxy-core` 与日志采集在后台运行；需要改配置或查日志时通过托盘 `Open` 按需重建主窗口。
- **托盘右键直接启停客户端**：在托盘菜单顶部新增 `Start client` / `Stop client` 菜单项，可根据当前 `proxy-core` 子进程运行状态动态切换文案，并同步更新托盘悬停提示（`Rama Proxy Client (Running)` / `(Stopped)`）。若在托盘点击启动但配置校验或启动失败，自动打开主窗口展示错误提示。
- **启动自启**：新增 `Auto-start client on launch`（持久化字段 `auto_start_client`），可配合简化模式实现启动即后台静默运行代理。

### 5. 客户端核心按需唤醒与两阶段空闲休眠（假死模式）

- **按需建池与按需心跳**：`TunnelPool` 与客户端运行时默认以 `Dormant`（休眠）启动，不预建空闲隧道、不建立心跳控制连接、不运行周期轮询定时器，彻底减少移动端后台唤醒提示与桌面端空闲资源占用。
- **请求唤醒与计时器重置**：收到本地 SOCKS5 请求后立即切至 `Active`，复用已有预留隧道或新建隧道服务请求，并在后台补足 `pool_size` 与开启心跳；每次新请求都会刷新活跃时间戳并立即重置空闲定时器。
- **两阶段递进休眠**：无活跃连接且空闲满 5 分钟后进入 `HeartbeatGrace`，关闭并清空全部预留隧道、保持心跳继续在线 5 分钟；若再无请求（累计 10 分钟），则主动断开心跳连接并暂停所有后台定时器回到 `Dormant` 休眠态，等待下一次本地请求唤醒。

## 配置示例

### 无认证上游

```toml
[upstream]
address = "10.0.0.2:1080"
connect_timeout_secs = 10
```

### 用户名密码认证上游

```toml
[upstream]
address = "proxy.example.com:1080"
username = "relay-user"
password = "relay-password"
connect_timeout_secs = 10
```

## 注意事项

- 若客户端需要转发 UDP 流量，上游 SOCKS5 服务必须支持 `UDP ASSOCIATE`。
- `server.outbound_ip_mode` 在配置 `[upstream]` 时作用于中继服务端连接上游地址及上游返回的 UDP relay 地址。
- 客户端与服务端之间的控制面（认证握手、心跳、Ping/Pong、统计 Unix Socket）仍由当前服务端处理，不透传给上游。

## 验证

已在 `1.5.0` 分支工作区执行并全部通过：

- `cargo fmt --all -- --check`
- `cargo test -p proxy-core`（共 17 项测试全部通过：`src/lib.rs` 1 项、`src/main.rs` 14 项、`tests/udp_associate.rs` 2 项，包含认证 + 原始域名透传、认证失败/拒绝/上游不可达不回退直连、UDP 转发与控制连接联动关闭、TOML 配置校验等测试）
- `cargo check -p proxy-gui`（Windows 原生托盘及简化模式编译检查通过）

## 升级说明

- 服务端启用 `[upstream]` 前请先使用 `rama-proxy server check -c <server.toml>` 校验配置及 `upstream` 摘要；仅升级服务端 `proxy-core` 时现有 `1.4.2` 客户端无需变更即可连接。
- Windows 桌面端用户建议同步升级 `proxy-gui.exe`，彻底消除托盘初始化/重建失败时的单核 CPU 空转问题。