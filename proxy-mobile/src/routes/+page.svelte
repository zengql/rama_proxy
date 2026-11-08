<script lang="ts">
  import { invoke, isTauri } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';

  type ClientSettings = {
    serverAddr: string;
    sharedSecret: string;
    clientId: string;
    socks5Port: number;
    poolSize: number;
    udpEnabled: boolean;
    tlsEnabled: boolean;
    tlsServerName: string;
    tlsCaCertPath: string;
  };

  type TunnelPoolStats = {
    maxIdleSize: number;
    warmIdleTarget: number;
    idle: number;
    inspectingIdle: number;
    connecting: number;
    active: number;
    consecutiveFailures: number;
    nextRefillAllowedInSecs: number | null;
    createdTotal: number;
    failedTotal: number;
    reapedStaleTotal: number;
    lastSuccessAgeSecs: number | null;
    lastRefillError: string | null;
  };

  type ClientStatus = {
    running: boolean;
    socks5Bind: string;
    serverAddr: string;
    startedAt: number | null;
    processId: number;
    lastError: string | null;
    poolStats: TunnelPoolStats | null;
    foregroundServiceRunning: boolean;
    foregroundServiceError: string | null;
    systemRestarted: boolean;
    batteryOptimizationIgnored: boolean;
    wakeLockHeld: boolean;
    wifiLockHeld: boolean;
    resumePending: boolean;
  };

  type LogRecord = {
    timestampMs: number;
    line: string;
  };

  type ImportedCaCertificate = {
    path: string;
    certificateCount: number;
  };

  const MAX_CA_CERT_BYTES = 512 * 1024;

  const emptySettings: ClientSettings = {
    serverAddr: '',
    sharedSecret: '',
    clientId: '',
    socks5Port: 1080,
    poolSize: 4,
    udpEnabled: false,
    tlsEnabled: false,
    tlsServerName: '',
    tlsCaCertPath: ''
  };

  let settings = $state<ClientSettings>({ ...emptySettings });
  let status = $state<ClientStatus>({
    running: false,
    socks5Bind: '127.0.0.1:1080',
    serverAddr: '',
    startedAt: null,
    processId: 0,
    lastError: null,
    poolStats: null,
    foregroundServiceRunning: false,
    foregroundServiceError: null,
    systemRestarted: false,
    batteryOptimizationIgnored: false,
    wakeLockHeld: false,
    wifiLockHeld: false,
    resumePending: false
  });
  let logs = $state<LogRecord[]>([]);
  let autoRefreshLogs = $state(true);
  let visibleLogs = $derived(logs.slice(-300).reverse());
  let poolStats = $derived(status.poolStats);
  let busy = $state(false);
  let certificateBusy = $state(false);
  let batteryBusy = $state(false);
  let restoring = $state(false);
  let loading = $state(true);
  let message = $state('');
  let advancedOpen = $state(false);
  let certificateInput = $state<HTMLInputElement>();
  let certificateFileName = $derived(fileNameFromPath(settings.tlsCaCertPath));
  let hasCertificate = $derived(settings.tlsCaCertPath.trim().length > 0);

  const tauri = isTauri();

  onMount(() => {
    void initialize();
    const timer = window.setInterval(() => {
      if (tauri) void refreshDiagnostics();
    }, 2000);
    const handleVisibilityChange = () => {
      if (!tauri || document.visibilityState !== "visible") return;
      void refreshDiagnostics().then(() => restoreIfNeeded("应用回到前台"));
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  });

  async function initialize() {
    if (!tauri) {
      loading = false;
      message = '浏览器预览模式：请通过 Tauri 或 Android 启动应用。';
      return;
    }

    try {
      settings = await invoke<ClientSettings>('load_config');
      if (!settings.clientId) {
        settings.clientId = `android-${crypto.randomUUID()}`;
      }
      await refreshDiagnostics();
      await restoreIfNeeded("应用启动");
    } catch (error) {
      message = errorText(error);
    } finally {
      loading = false;
    }
  }

  async function refreshDiagnostics() {
    await refreshStatus();
    if (autoRefreshLogs) {
      await refreshLogs();
    }
  }

  async function refreshLogs() {
    try {
      logs = await invoke<LogRecord[]>('get_recent_logs');
    } catch (error) {
      console.error('读取运行日志失败', error);
    }
  }

  async function refreshStatus() {
    try {
      status = await invoke<ClientStatus>('client_status');
    } catch (error) {
      status = { ...status, lastError: errorText(error) };
    }
  }

  function normalizedSettings(): ClientSettings {
    return {
      ...settings,
      socks5Port: Number(settings.socks5Port),
      poolSize: Number(settings.poolSize)
    };
  }

  async function restoreIfNeeded(reason: string) {
    if (!tauri || restoring || busy || !status.resumePending || status.running) return;
    restoring = true;
    message = `${reason}，检测到上次代理仍在运行，正在自动恢复本地 SOCKS5…`;
    try {
      await startClient(true);
    } finally {
      restoring = false;
    }
  }

  async function saveConfig() {
    if (!requireTauri()) return;
    busy = true;
    message = '';
    try {
      await invoke('save_config', { settings: normalizedSettings() });
      message = '配置已保存。';
      await refreshStatus();
    } catch (error) {
      message = errorText(error);
    } finally {
      busy = false;
    }
  }

  async function startClient(automatic = false) {
    if (!requireTauri()) return;
    if (settings.tlsEnabled && !hasCertificate) {
      message = '启用 TLS 时请先选择 PEM CA 证书。';
      return;
    }
    busy = true;
    message = '';
    try {
      status = await invoke<ClientStatus>('start_client', {
        settings: normalizedSettings()
      });
      const resultText = status.foregroundServiceError
        ? `本地 SOCKS5 已启动，但前台服务启动失败：${status.foregroundServiceError}`
        : `本地 SOCKS5 已启动：${status.socks5Bind}`;
      message = automatic ? `已自动恢复上次运行状态。${resultText}` : resultText;
      await refreshLogs();
    } catch (error) {
      message = errorText(error);
      await refreshStatus();
    } finally {
      busy = false;
    }
  }

  async function stopClient() {
    if (!requireTauri()) return;
    busy = true;
    message = '';
    try {
      status = await invoke<ClientStatus>('stop_client');
      message = '本地 SOCKS5 已停止。';
      await refreshLogs();
    } catch (error) {
      message = errorText(error);
      await refreshStatus();
    } finally {
      busy = false;
    }
  }

  function chooseCaCertificate() {
    if (!requireTauri() || certificateBusy) return;
    if (!certificateInput) {
      message = '当前环境无法打开系统文件选择器。';
      return;
    }
    certificateInput.value = '';
    certificateInput.click();
  }

  async function handleCaCertificateSelected(event: Event) {
    if (!requireTauri()) return;
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    input.value = '';
    if (!file) return;

    certificateBusy = true;
    busy = true;
    message = '';

    try {
      if (file.size > MAX_CA_CERT_BYTES) {
        throw new Error('证书文件过大，最大支持 512 KiB。');
      }

      const bytes = await readFileBytes(file);
      let certificate: string;
      try {
        certificate = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      } catch {
        throw new Error('证书文件不是有效的 UTF-8 PEM 文本。');
      }

      const imported = await invoke<ImportedCaCertificate>('import_ca_certificate', {
        certificate
      });
      settings.tlsCaCertPath = imported.path;
      message = `已导入 ${file.name}，证书数量：${imported.certificateCount}。`;
    } catch (error) {
      message = errorText(error);
    } finally {
      certificateBusy = false;
      busy = false;
    }
  }

  async function removeCaCertificate() {
    if (!requireTauri()) return;
    certificateBusy = true;
    busy = true;
    message = '';
    try {
      await invoke('remove_ca_certificate');
      settings.tlsCaCertPath = '';
      message = '已移除应用私有目录中的 CA 证书。';
    } catch (error) {
      message = errorText(error);
    } finally {
      certificateBusy = false;
      busy = false;
    }
  }

  function readFileBytes(file: File): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        if (!(reader.result instanceof ArrayBuffer)) {
          reject(new Error('读取证书文件失败。'));
          return;
        }
        resolve(new Uint8Array(reader.result));
      };
      reader.onerror = () => reject(new Error('读取证书文件失败。'));
      reader.onabort = () => reject(new Error('已取消读取证书文件。'));
      reader.readAsArrayBuffer(file);
    });
  }

  function fileNameFromPath(path: string): string {
    const value = path.trim();
    if (!value) return '';
    return value.split(/[\\/]/).pop() || value;
  }

  function requireTauri(): boolean {
    if (tauri) return true;
    message = '该操作只能在 Android/Tauri 应用中执行。';
    return false;
  }

  function errorText(error: unknown): string {
    if (typeof error === 'string') return error;
    if (error instanceof Error) return error.message;
    return JSON.stringify(error);
  }

  async function clearLogs() {
    if (!requireTauri()) return;
    try {
      await invoke('clear_logs');
      logs = [];
      message = '运行日志已清空。';
    } catch (error) {
      message = errorText(error);
    }
  }

  async function requestBatteryOptimizationExemption() {
    if (!requireTauri() || batteryBusy) return;
    batteryBusy = true;
    message = '';
    try {
      await invoke('request_battery_optimization_exemption');
      await refreshStatus();
      message = status.batteryOptimizationIgnored
        ? '已允许后台运行，系统将减少对代理进程的电池优化限制。'
        : '已打开系统设置，请选择“允许后台运行”或“不限制电池使用”。';
    } catch (error) {
      message = errorText(error);
    } finally {
      batteryBusy = false;
    }
  }

  async function copyLogs() {
    if (!logs.length) return;
    const content = logs.map((record) => `${formatLogTime(record.timestampMs)} ${record.line}`).join('\n');
    try {
      await navigator.clipboard.writeText(content);
      message = '运行日志已复制。';
    } catch {
      message = '当前环境无法直接复制日志，请长按日志文本选择复制。';
    }
  }

  function formatLogTime(timestampMs: number): string {
    const date = new Date(timestampMs);
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    const millis = String(timestampMs % 1000).padStart(3, '0');
    return `${hours}:${minutes}:${seconds}.${millis}`;
  }

  async function copyAddress() {
    try {
      await navigator.clipboard.writeText(status.socks5Bind);
      message = '已复制本地代理地址。';
    } catch {
      message = `本地地址：${status.socks5Bind}`;
    }
  }

  function formatStartedAt(value: number | null): string {
    if (!value) return '';
    return new Date(value * 1000).toLocaleTimeString('zh-CN', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  }
</script>

<svelte:head>
  <title>Rama Proxy Mobile</title>
  <meta
    name="description"
    content="在 Android 设备上提供仅绑定本机的 SOCKS5 代理端口，不使用 VPN。"
  />
</svelte:head>

<div class="shell">
  <header>
    <div class="brand-mark">R</div>
    <div>
      <p class="eyebrow">RAMA PROXY</p>
      <h1>移动端本地代理</h1>
    </div>
    <span class:danger={!status.running} class="state-pill">
      <span class="dot"></span>
      {status.running ? '运行中' : '已停止'}
    </span>
  </header>

  <main>
    <section class="hero" class:live={status.running}>
      <div class="hero-copy">
        <p class="label">本地 SOCKS5 端口</p>
        <button class="address" type="button" onclick={copyAddress} title="点击复制">
          {status.socks5Bind}
        </button>
        <p class="hint">
          仅监听 <strong>127.0.0.1</strong>，不创建 VPN，也不向局域网开放端口。
        </p>
      </div>
      <div class="pulse" aria-hidden="true">
        <span></span>
      </div>
    </section>

    {#if status.lastError}
      <div class="alert">
        <strong>最近一次错误</strong>
        <p>{status.lastError}</p>
      </div>
    {/if}

    {#if message}
      <div class="message">{message}</div>
    {/if}

    <section class="card">
      <div class="section-title">
        <div>
          <p class="label">远程隧道</p>
          <h2>服务器配置</h2>
        </div>
        <span class="tag">TCP</span>
      </div>

      <fieldset disabled={status.running || busy || loading}>
        <label>
          <span>服务器地址</span>
          <input
            bind:value={settings.serverAddr}
            placeholder="203.0.113.10:8443"
            autocomplete="off"
            spellcheck="false"
          />
          <small>IP 地址和端口，例如 1.2.3.4:8443。</small>
        </label>

        <label>
          <span>共享密钥</span>
          <input
            bind:value={settings.sharedSecret}
            type="password"
            placeholder="与服务器一致的 shared secret"
            autocomplete="off"
          />
        </label>

        <div class="grid">
          <label>
            <span>本地端口</span>
            <input bind:value={settings.socks5Port} type="number" min="1" max="65535" />
          </label>
          <label>
            <span>连接池</span>
            <input bind:value={settings.poolSize} type="number" min="1" max="64" />
          </label>
        </div>

        <label>
          <span>客户端 ID</span>
          <input bind:value={settings.clientId} autocomplete="off" spellcheck="false" />
        </label>
      </fieldset>

      <button
        class="advanced-toggle"
        type="button"
        onclick={() => (advancedOpen = !advancedOpen)}
        aria-expanded={advancedOpen}
      >
        <span>高级选项</span>
        <span class="chevron" class:open={advancedOpen}>⌄</span>
      </button>

      {#if advancedOpen}
        <fieldset disabled={status.running || busy || loading || certificateBusy}>
          <label class="switch-row">
            <span>
              <strong>UDP ASSOCIATE</strong>
              <small>开启后支持 SOCKS5 UDP ASSOCIATE；不会影响 TCP 连接池。</small>
            </span>
            <input bind:checked={settings.udpEnabled} type="checkbox" />
          </label>

          <label class="switch-row">
            <span>
              <strong>启用 TLS</strong>
              <small>远程隧道使用 TLS 时开启。</small>
            </span>
            <input bind:checked={settings.tlsEnabled} type="checkbox" />
          </label>

          {#if settings.tlsEnabled}
            <label>
              <span>TLS 服务器名称</span>
              <input bind:value={settings.tlsServerName} autocomplete="off" spellcheck="false" />
            </label>
            <div class="certificate-field">
              <span>CA 证书</span>
              <div class="certificate-actions">
                <button
                  class="certificate-pick"
                  type="button"
                  onclick={chooseCaCertificate}
                  disabled={certificateBusy}
                >
                  {certificateBusy
                    ? '正在导入…'
                    : hasCertificate
                      ? '重新选择 PEM 证书'
                      : '选择 PEM 证书'}
                </button>
                {#if hasCertificate}
                  <button
                    class="certificate-remove"
                    type="button"
                    onclick={removeCaCertificate}
                    disabled={certificateBusy}
                  >
                    移除
                  </button>
                {/if}
              </div>
              {#if hasCertificate}
                <div class="certificate-current">
                  <span aria-hidden="true">✓</span>
                  <strong>{certificateFileName}</strong>
                  <small>已复制到应用私有目录，无需手动填写路径。</small>
                </div>
              {:else}
                <small>启用 TLS 时必填。通过系统文件选择器选取 PEM CA 证书。</small>
              {/if}
              <input
                class="certificate-file-input"
                bind:this={certificateInput}
                type="file"
                accept="*/*"
                onchange={handleCaCertificateSelected}
              />
            </div>
          {/if}
        </fieldset>
      {/if}

      <div class="actions">
        {#if status.running}
          <button class="primary stop" type="button" onclick={stopClient} disabled={busy}>
            {busy ? '正在停止…' : '停止代理'}
          </button>
        {:else}
          <button class="primary" type="button" onclick={() => startClient(false)} disabled={busy || loading}>
            {busy ? '正在启动…' : '启动本地代理'}
          </button>
          <button class="secondary" type="button" onclick={saveConfig} disabled={busy || loading}>
            保存配置
          </button>
        {/if}
      </div>
    </section>

    <section class="card diagnostics-card">
      <div class="section-title">
        <div>
          <p class="label">运行诊断</p>
          <h2>连接池状态</h2>
        </div>
        <span class="tag">POOL</span>
      </div>

      {#if poolStats}
        <div class="metric-grid">
          <div class="metric">
            <span>空闲</span>
            <strong>{poolStats.idle}</strong>
            <small>目标 {poolStats.warmIdleTarget} · 上限 {poolStats.maxIdleSize}</small>
          </div>
          <div class="metric">
            <span>检查中</span>
            <strong>{poolStats.inspectingIdle}</strong>
            <small>正在验证空闲隧道</small>
          </div>
          <div class="metric">
            <span>建连中</span>
            <strong>{poolStats.connecting}</strong>
            <small>正在建立新隧道</small>
          </div>
          <div class="metric">
            <span>活跃</span>
            <strong>{poolStats.active}</strong>
            <small>当前正在转发</small>
          </div>
          <div class="metric" class:warning={poolStats.consecutiveFailures > 0}>
            <span>连续失败</span>
            <strong>{poolStats.consecutiveFailures}</strong>
            <small>补池失败累计次数</small>
          </div>
          <div class="metric" class:warning={poolStats.nextRefillAllowedInSecs !== null}>
            <span>补池冷却</span>
            <strong>
              {poolStats.nextRefillAllowedInSecs === null
                ? '0'
                : poolStats.nextRefillAllowedInSecs}
            </strong>
            <small>{poolStats.nextRefillAllowedInSecs === null ? '当前可补池' : '秒后重试'}</small>
          </div>
          <div class="metric">
            <span>Created</span>
            <strong>{poolStats.createdTotal}</strong>
            <small>Successful tunnel creations</small>
          </div>
          <div class="metric" class:warning={poolStats.failedTotal > 0}>
            <span>Failed</span>
            <strong>{poolStats.failedTotal}</strong>
            <small>Failed tunnel creations</small>
          </div>
          <div class="metric" class:warning={poolStats.reapedStaleTotal > 0}>
            <span>Stale reaped</span>
            <strong>{poolStats.reapedStaleTotal}</strong>
            <small>Dead pooled tunnels removed</small>
          </div>
          <div class="metric">
            <span>Last success</span>
            <strong>{poolStats.lastSuccessAgeSecs === null ? '-' : `${poolStats.lastSuccessAgeSecs}s`}</strong>
            <small>Age of the latest successful refill</small>
          </div>
        </div>
        {#if poolStats.consecutiveFailures > 0}
          <p class="pool-warning">连接池正在退避重试，请查看下方日志中的 <code>failed to create idle tunnel</code>。</p>
        {/if}
        {#if poolStats.lastRefillError}
          <p class="pool-warning">Last refill error: <code>{poolStats.lastRefillError}</code></p>
        {/if}
      {:else}
        <p class="empty-hint">启动代理后显示连接池实时状态。</p>
      {/if}

      <div class:ok={status.foregroundServiceRunning} class="service-row">
        <span class="dot"></span>
        <span>Android 前台服务</span>
        <strong>
          {status.running
            ? status.foregroundServiceRunning
              ? '运行中'
              : status.foregroundServiceError
                ? '启动失败'
                : '未启动'
            : '未运行'}
        </strong>
      </div>
      {#if status.foregroundServiceError}
        <p class="service-error">{status.foregroundServiceError}</p>
      {/if}
      {#if status.systemRestarted}
        <p class="pool-warning">
          Android 已重新创建前台服务，但 Rust SOCKS5 不会由系统自动恢复。应用下次打开或回到前台时会尝试自动恢复。
        </p>
      {/if}

      {#if status.processId}
        <p class="service-note">
          PID {status.processId} · WakeLock {status.wakeLockHeld ? "已持有" : "未持有"} · Wi-Fi Lock {status.wifiLockHeld ? "已持有" : "未持有"}
        </p>
      {/if}

      <button
        class="battery-action"
        type="button"
        onclick={requestBatteryOptimizationExemption}
        disabled={batteryBusy || status.batteryOptimizationIgnored}
      >
        {batteryBusy
          ? '正在打开系统设置…'
          : status.batteryOptimizationIgnored
            ? '已允许后台运行'
            : '允许后台运行 / 忽略电池优化'}
      </button>
      <p class="service-note">
        WakeLock、Wi-Fi Lock 和非 VPN 前台服务只能降低被系统终止的概率。小米、华为、OPPO、vivo 等设备仍需在厂商设置中允许自启动和后台运行。
      </p>
    </section>

    <section class="card logs-card">
      <div class="section-title">
        <div>
          <p class="label">诊断日志</p>
          <h2>运行日志</h2>
        </div>
        <div class="log-actions">
          <label class="inline-toggle">
            <input bind:checked={autoRefreshLogs} type="checkbox" />
            自动
          </label>
          <button type="button" onclick={refreshLogs}>刷新</button>
          <button type="button" onclick={copyLogs} disabled={!logs.length}>复制</button>
          <button type="button" onclick={clearLogs} disabled={!logs.length}>清空</button>
        </div>
      </div>
      {#if visibleLogs.length}
        <div class="log-list" aria-live="polite">
          {#each visibleLogs as record, index (record.timestampMs + '-' + index)}
            <div class="log-line">
              <time>{formatLogTime(record.timestampMs)}</time>
              <span>{record.line}</span>
            </div>
          {/each}
        </div>
        <p class="log-note">
          显示最近 {visibleLogs.length} 条，共保留 {logs.length} 条。日志同时写入应用私有目录的 rama-proxy.log，也可在 adb logcat 中过滤 RamaProxy。
        </p>
      {:else}
        <p class="empty-hint">暂无日志。启动代理后这里会显示隧道建连、连接池和 UDP 信息。</p>
      {/if}
    </section>
    <section class="facts">
      <div class="fact">
        <span class="fact-icon">↳</span>
        <div>
          <strong>无 VPN 权限</strong>
          <p>应用不请求 VpnService，不接管设备全局流量。</p>
        </div>
      </div>
      <div class="fact">
        <span class="fact-icon">⌁</span>
        <div>
          <strong>本机回环地址</strong>
          <p>其他应用可将代理设置为 {status.socks5Bind}。</p>
        </div>
      </div>
      <div class="fact">
        <span class="fact-icon">◷</span>
        <div>
          <strong>后台运行限制</strong>
          <p>使用非 VPN 前台服务和 WakeLock 保持运行，但厂商极端省电策略仍可能终止服务。</p>
        </div>
      </div>
    </section>

    {#if status.running && status.startedAt}
      <p class="started-at">本次启动于 {formatStartedAt(status.startedAt)}</p>
    {/if}
  </main>
</div>

<style>
  :global(:root) {
    color-scheme: dark;
    font-family:
      Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans SC',
      sans-serif;
    background: #06101d;
    color: #edf6ff;
  }

  :global(*) {
    box-sizing: border-box;
  }

  :global(body) {
    margin: 0;
    min-width: 320px;
    min-height: 100vh;
    background:
      radial-gradient(circle at 12% -5%, rgba(77, 200, 255, 0.22), transparent 35%),
      radial-gradient(circle at 100% 45%, rgba(39, 255, 169, 0.09), transparent 32%),
      linear-gradient(155deg, #071523 0%, #050b14 60%, #07111f 100%);
  }

  :global(button),
  :global(input) {
    font: inherit;
  }

  .shell {
    width: min(100%, 540px);
    min-height: 100vh;
    margin: 0 auto;
    padding: max(18px, env(safe-area-inset-top)) 18px max(28px, env(safe-area-inset-bottom));
  }

  header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 22px;
  }

  .brand-mark {
    display: grid;
    width: 42px;
    height: 42px;
    place-items: center;
    border: 1px solid rgba(105, 223, 255, 0.45);
    border-radius: 14px;
    background: linear-gradient(145deg, rgba(46, 188, 255, 0.28), rgba(12, 48, 72, 0.6));
    box-shadow: inset 0 1px rgba(255, 255, 255, 0.16), 0 12px 30px rgba(0, 0, 0, 0.25);
    color: #8ee9ff;
    font-size: 22px;
    font-weight: 800;
  }

  header h1 {
    margin: 0;
    font-size: 20px;
    letter-spacing: -0.02em;
  }

  .eyebrow,
  .label {
    margin: 0 0 5px;
    color: #70a0b9;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 0.16em;
  }

  .state-pill {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    margin-left: auto;
    padding: 7px 10px;
    border: 1px solid rgba(60, 246, 173, 0.25);
    border-radius: 999px;
    background: rgba(34, 210, 144, 0.08);
    color: #69f0b6;
    font-size: 12px;
    font-weight: 700;
  }

  .state-pill.danger {
    border-color: rgba(148, 177, 194, 0.16);
    background: rgba(148, 177, 194, 0.07);
    color: #91a8b7;
  }

  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: currentColor;
    box-shadow: 0 0 10px currentColor;
  }

  main {
    display: grid;
    gap: 16px;
  }

  .hero {
    position: relative;
    overflow: hidden;
    display: flex;
    min-height: 150px;
    align-items: center;
    justify-content: space-between;
    padding: 22px;
    border: 1px solid rgba(83, 184, 231, 0.2);
    border-radius: 24px;
    background:
      linear-gradient(120deg, rgba(20, 75, 108, 0.58), rgba(10, 26, 43, 0.86)),
      rgba(12, 25, 40, 0.85);
    box-shadow: 0 18px 50px rgba(0, 0, 0, 0.28);
  }

  .hero::after {
    position: absolute;
    right: -70px;
    bottom: -110px;
    width: 240px;
    height: 240px;
    border: 1px solid rgba(76, 225, 255, 0.11);
    border-radius: 50%;
    content: '';
  }

  .hero.live {
    border-color: rgba(62, 242, 174, 0.34);
    background:
      linear-gradient(120deg, rgba(12, 91, 79, 0.54), rgba(8, 29, 38, 0.91)),
      rgba(12, 25, 40, 0.85);
  }

  .hero-copy {
    position: relative;
    z-index: 1;
    max-width: calc(100% - 84px);
  }

  .address {
    display: block;
    max-width: 100%;
    overflow: hidden;
    padding: 0;
    border: 0;
    background: transparent;
    color: #f5fbff;
    font-family: 'SFMono-Regular', Consolas, monospace;
    font-size: clamp(22px, 7vw, 30px);
    font-weight: 750;
    letter-spacing: -0.04em;
    text-align: left;
    text-overflow: ellipsis;
    white-space: nowrap;
    cursor: pointer;
  }

  .address:active {
    opacity: 0.7;
  }

  .hint {
    margin: 12px 0 0;
    color: #92afc0;
    font-size: 12px;
    line-height: 1.6;
  }

  .hint strong {
    color: #c7e9f5;
    font-weight: 700;
  }

  .pulse {
    position: relative;
    z-index: 1;
    display: grid;
    width: 66px;
    height: 66px;
    flex: 0 0 auto;
    place-items: center;
    border: 1px solid rgba(103, 199, 232, 0.18);
    border-radius: 50%;
  }

  .pulse::before,
  .pulse::after,
  .pulse span {
    position: absolute;
    border-radius: 50%;
    content: '';
  }

  .pulse::before {
    width: 44px;
    height: 44px;
    border: 1px solid rgba(103, 199, 232, 0.22);
  }

  .pulse::after {
    width: 20px;
    height: 20px;
    background: rgba(106, 213, 248, 0.2);
    box-shadow: 0 0 26px rgba(61, 213, 255, 0.22);
  }

  .pulse span {
    width: 8px;
    height: 8px;
    background: #73ddf9;
    box-shadow: 0 0 14px #48cfff;
  }

  .live .pulse span,
  .live .pulse::after {
    background: #65f1b5;
    box-shadow: 0 0 24px rgba(60, 244, 168, 0.7);
  }

  .message,
  .alert {
    padding: 13px 15px;
    border: 1px solid rgba(84, 194, 235, 0.2);
    border-radius: 14px;
    background: rgba(38, 119, 153, 0.12);
    color: #a8d8e8;
    font-size: 12px;
    line-height: 1.5;
  }

  .alert {
    border-color: rgba(255, 127, 127, 0.25);
    background: rgba(180, 54, 73, 0.12);
    color: #ffc3c9;
  }

  .alert strong {
    display: block;
    margin-bottom: 4px;
    font-size: 11px;
  }

  .alert p {
    margin: 0;
    word-break: break-word;
  }

  .card {
    padding: 20px;
    border: 1px solid rgba(137, 185, 211, 0.14);
    border-radius: 24px;
    background: rgba(9, 20, 33, 0.82);
    box-shadow: 0 20px 45px rgba(0, 0, 0, 0.2);
    backdrop-filter: blur(16px);
  }

  .section-title {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    margin-bottom: 18px;
  }

  .section-title h2 {
    margin: 0;
    font-size: 18px;
    letter-spacing: -0.02em;
  }

  .tag {
    padding: 5px 8px;
    border: 1px solid rgba(104, 207, 244, 0.18);
    border-radius: 7px;
    background: rgba(91, 212, 255, 0.07);
    color: #77cae5;
    font-family: 'SFMono-Regular', Consolas, monospace;
    font-size: 10px;
  }

  fieldset {
    display: grid;
    gap: 15px;
    min-width: 0;
    margin: 0;
    padding: 0;
    border: 0;
  }

  fieldset:disabled {
    opacity: 0.65;
  }

  label {
    display: grid;
    gap: 7px;
    min-width: 0;
  }

  label > span {
    color: #b8d1df;
    font-size: 12px;
    font-weight: 650;
  }

  label small {
    color: #627f91;
    font-size: 10px;
    line-height: 1.45;
  }

  .certificate-field {
    display: grid;
    gap: 8px;
    min-width: 0;
  }

  .certificate-field > span {
    color: #b8d1df;
    font-size: 12px;
    font-weight: 650;
  }

  .certificate-field small {
    color: #627f91;
    font-size: 10px;
    line-height: 1.45;
  }

  .certificate-actions {
    display: flex;
    gap: 8px;
  }

  button.certificate-pick,
  button.certificate-remove {
    min-height: 42px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 700;
    cursor: pointer;
  }

  button.certificate-pick {
    flex: 1;
    border: 1px solid rgba(104, 207, 244, 0.3);
    background: linear-gradient(135deg, rgba(48, 172, 218, 0.25), rgba(19, 89, 122, 0.34));
    color: #9ee9ff;
  }

  button.certificate-remove {
    padding: 0 14px;
    border: 1px solid rgba(255, 143, 143, 0.2);
    background: rgba(88, 28, 38, 0.3);
    color: #ffb4b4;
  }

  .certificate-current {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 2px 8px;
    align-items: center;
    padding: 10px 12px;
    border: 1px solid rgba(67, 224, 157, 0.16);
    border-radius: 12px;
    background: rgba(21, 92, 67, 0.14);
  }

  .certificate-current > span {
    grid-row: 1 / span 2;
    color: #5ee8ad;
    font-size: 15px;
    font-weight: 800;
  }

  .certificate-current strong {
    min-width: 0;
    overflow: hidden;
    color: #bfe9d9;
    font-size: 11px;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .certificate-current small {
    grid-column: 2;
  }

  .certificate-file-input {
    display: none;
  }

  input:not([type='checkbox']):not([type='file']) {
    width: 100%;
    height: 44px;
    padding: 0 13px;
    border: 1px solid rgba(121, 175, 204, 0.18);
    border-radius: 12px;
    outline: none;
    background: rgba(2, 10, 18, 0.52);
    color: #e7f5ff;
    font-size: 13px;
    transition:
      border-color 150ms ease,
      box-shadow 150ms ease;
  }

  input:not([type='checkbox']):not([type='file']):focus {
    border-color: rgba(83, 211, 255, 0.55);
    box-shadow: 0 0 0 3px rgba(64, 191, 238, 0.09);
  }

  input::placeholder {
    color: #496778;
  }

  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }

  .advanced-toggle {
    display: flex;
    width: 100%;
    align-items: center;
    justify-content: space-between;
    margin-top: 18px;
    padding: 12px 0;
    border: 0;
    border-top: 1px solid rgba(137, 185, 211, 0.1);
    background: transparent;
    color: #8db2c4;
    font-size: 12px;
    font-weight: 650;
    cursor: pointer;
  }

  .chevron {
    font-size: 18px;
    transition: transform 160ms ease;
  }

  .chevron.open {
    transform: rotate(180deg);
  }

  .switch-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 12px;
    border: 1px solid rgba(121, 175, 204, 0.12);
    border-radius: 13px;
    background: rgba(4, 14, 24, 0.35);
  }

  .switch-row > span {
    display: grid;
    gap: 4px;
  }

  .switch-row strong {
    color: #c9e0eb;
    font-size: 12px;
  }

  .switch-row input {
    width: 40px;
    height: 22px;
    flex: 0 0 auto;
    accent-color: #42dca0;
  }

  .actions {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 10px;
    margin-top: 20px;
  }

  .actions:has(.primary:only-child) {
    grid-template-columns: 1fr;
  }

  button.primary,
  button.secondary {
    min-height: 48px;
    padding: 0 18px;
    border-radius: 13px;
    font-size: 13px;
    font-weight: 750;
    cursor: pointer;
  }

  button.primary {
    border: 1px solid rgba(114, 230, 255, 0.36);
    background: linear-gradient(135deg, #36bde9, #1b8fbd);
    box-shadow: 0 10px 25px rgba(9, 145, 195, 0.23);
    color: #03131d;
  }

  button.primary.stop {
    border-color: rgba(255, 143, 143, 0.35);
    background: linear-gradient(135deg, #ffb0ad, #e86e73);
    box-shadow: 0 10px 25px rgba(190, 62, 78, 0.2);
    color: #2c070a;
  }

  button.secondary {
    border: 1px solid rgba(126, 184, 211, 0.18);
    background: rgba(16, 38, 55, 0.7);
    color: #b7d8e7;
  }

  button:disabled {
    cursor: not-allowed;
    opacity: 0.55;
  }

  .diagnostics-card .section-title,
  .logs-card .section-title {
    margin-bottom: 14px;
  }

  .metric-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 8px;
  }

  .metric {
    min-width: 0;
    padding: 11px 10px;
    border: 1px solid rgba(121, 175, 204, 0.13);
    border-radius: 13px;
    background: rgba(4, 14, 24, 0.38);
  }

  .metric.warning {
    border-color: rgba(255, 190, 100, 0.28);
    background: rgba(123, 76, 18, 0.16);
  }

  .metric > span {
    display: block;
    color: #7797a9;
    font-size: 10px;
    font-weight: 700;
  }

  .metric > strong {
    display: block;
    margin: 3px 0 2px;
    color: #e0f5ff;
    font-family: 'SFMono-Regular', Consolas, monospace;
    font-size: 22px;
    line-height: 1;
  }

  .metric > small {
    display: block;
    overflow: hidden;
    color: #5e7b8c;
    font-size: 9px;
    line-height: 1.35;
    text-overflow: ellipsis;
  }

  .pool-warning,
  .service-error {
    margin: 11px 0 0;
    color: #eac486;
    font-size: 10px;
    line-height: 1.5;
    overflow-wrap: anywhere;
  }

  .pool-warning code {
    color: #ffe0a3;
    font-family: 'SFMono-Regular', Consolas, monospace;
  }

  .service-row {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 12px;
    padding-top: 12px;
    border-top: 1px solid rgba(137, 185, 211, 0.1);
    color: #87a8b9;
    font-size: 11px;
  }

  .service-row .dot {
    width: 6px;
    height: 6px;
    flex: 0 0 auto;
    background: #8aa6b4;
    box-shadow: none;
  }

  .service-row.ok .dot {
    background: #65f1b5;
    box-shadow: 0 0 10px rgba(60, 244, 168, 0.65);
  }

  .service-row strong {
    margin-left: auto;
    color: #c7e0eb;
    font-size: 10px;
  }

  .battery-action {
    width: 100%;
    min-height: 38px;
    margin-top: 12px;
    border: 1px solid rgba(104, 207, 244, 0.2);
    border-radius: 11px;
    background: rgba(19, 57, 77, 0.62);
    color: #a9dff0;
    font-size: 11px;
    font-weight: 700;
    cursor: pointer;
  }

  .battery-action:disabled {
    cursor: default;
    opacity: 0.72;
  }

  .service-note {
    margin: 8px 0 0;
    color: #5f7d8e;
    font-size: 9px;
    line-height: 1.5;
  }

  .log-actions {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 6px;
    flex-wrap: wrap;
  }

  .inline-toggle {
    display: inline-flex;
    grid-template-columns: none;
    align-items: center;
    gap: 4px;
    color: #8eb2c3;
    font-size: 10px;
    font-weight: 700;
    white-space: nowrap;
  }

  .inline-toggle input {
    width: 16px;
    height: 16px;
    accent-color: #42dca0;
  }

  .log-actions button {
    min-height: 28px;
    padding: 0 8px;
    border: 1px solid rgba(104, 207, 244, 0.2);
    border-radius: 8px;
    background: rgba(19, 57, 77, 0.62);
    color: #9ed9eb;
    font-size: 10px;
    font-weight: 700;
    cursor: pointer;
  }

  .log-actions button:disabled {
    cursor: not-allowed;
    opacity: 0.45;
  }

  .log-list {
    max-height: 300px;
    overflow: auto;
    padding: 8px;
    border: 1px solid rgba(121, 175, 204, 0.12);
    border-radius: 13px;
    background: rgba(1, 7, 13, 0.62);
  }

  .log-line {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    gap: 9px;
    padding: 4px 2px;
    border-bottom: 1px solid rgba(121, 175, 204, 0.06);
    color: #a9c6d4;
    font-family: 'SFMono-Regular', Consolas, monospace;
    font-size: 10px;
    line-height: 1.5;
  }

  .log-line:last-child {
    border-bottom: 0;
  }

  .log-line time {
    color: #5d899d;
    white-space: nowrap;
  }

  .log-line span {
    min-width: 0;
    overflow-wrap: anywhere;
    white-space: pre-wrap;
  }

  .log-note {
    margin: 9px 0 0;
    color: #5f7d8e;
    font-size: 9px;
    line-height: 1.45;
  }

  .empty-hint {
    margin: 0;
    color: #6f8d9d;
    font-size: 11px;
    line-height: 1.55;
  }
  .facts {
    display: grid;
    gap: 10px;
  }

  .fact {
    display: flex;
    gap: 12px;
    padding: 14px;
    border: 1px solid rgba(137, 185, 211, 0.1);
    border-radius: 16px;
    background: rgba(7, 18, 30, 0.58);
  }

  .fact-icon {
    display: grid;
    width: 30px;
    height: 30px;
    flex: 0 0 auto;
    place-items: center;
    border: 1px solid rgba(113, 208, 240, 0.16);
    border-radius: 9px;
    color: #6bc8e4;
  }

  .fact strong {
    display: block;
    margin-bottom: 3px;
    color: #b8d4e1;
    font-size: 11px;
  }

  .fact p {
    margin: 0;
    color: #648091;
    font-size: 10px;
    line-height: 1.5;
  }

  .started-at {
    margin: 2px 0 0;
    color: #5f7d8e;
    font-size: 10px;
    text-align: center;
  }

  @media (max-width: 380px) {
    .shell {
      padding-right: 13px;
      padding-left: 13px;
    }

    .hero,
    .card {
      border-radius: 20px;
    }

    .hero {
      padding: 18px;
    }

    .pulse {
      width: 54px;
      height: 54px;
    }

    .actions {
      grid-template-columns: 1fr;
    }
  }
</style>
