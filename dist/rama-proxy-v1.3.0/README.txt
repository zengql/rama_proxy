rama-proxy v1.3.0 (Windows 客户端 GUI 版)
=========================================

文件说明
--------
proxy-gui.exe   界面程序（双击运行），会自动拉起同目录下的 proxy-core.exe
proxy-core.exe  核心程序（客户端 CLI / 服务器 CLI），由 GUI 调用
config/         配置文件目录（程序以"当前工作目录"为基准读写 config/client.toml）

用法
----
1. 把整个目录放到任意位置（例：d:\tools\rama_proxy_tls\）。
2. 双击 proxy-gui.exe。
3. 点右上角 Settings：
   - Tunnel：填远程服务器地址(server_addr)、shared_secret、client_id
   - Local listeners：本机 SOCKS5 端口（Clash 等指向它）
   - TLS：勾选 Enable TLS 后填写 Server name 和 CA certificate 路径
   - 点 Save 保存到 config/client.toml
4. 点主界面 Enable 启动客户端，Disable 停止。

窗口关闭行为
------------
Settings -> Application -> Close button behavior：
- Ask            点 X 弹确认框（默认）
- Exit           点 X 直接退出
- Close to tray  点 X 收起到托盘（任务栏不再显示），从托盘图标可 Open / Exit

托盘说明
--------
- 托盘图标失效时（例如 Windows Explorer 重启），程序会自动重建托盘，并在界面顶部提示。
- 控制台输出区可勾选 Follow latest 自动跟随最新日志；手动滚动后会自动取消跟随。


命令行（proxy-core.exe，可选）
------------------------------
proxy-core.exe client --config config/client.toml      # 启动客户端
proxy-core.exe server --config config/server.toml      # 启动服务器
proxy-core.exe client init / check                     # 生成/校验配置
proxy-core.exe server init / check

TLS 证书（客户端）
------------------
gui 里勾选 Enable TLS 后填：
  Server name      = 服务器域名/IP（SNI，必须与证书 SAN 匹配）
  CA certificate   = 验证服务器证书的 CA，PEM 绝对路径，必填
  Client certificate / Client key = mTLS 双向认证时才填

服务器端 TLS 需手改 config/server.toml 的 [tls]：
  cert_path / key_path / require_client_auth / client_ca_cert_path

注意
----
- 证书仅支持 PEM 格式（.crt/.pem/.key），不支持 p12/jks。
- tls.insecure_skip_verify 为保留字段，开启 TLS 时校验会拒绝该项。