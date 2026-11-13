package com.zqliang.ramaproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.net.wifi.WifiManager
import android.os.PowerManager
import android.util.Log
import java.io.File

class ProxyForegroundService : Service() {
  private external fun nativeRuntimeBridge(dataDir: String, restore: Boolean): Boolean

  private var wakeLock: PowerManager.WakeLock? = null
  private var wifiLock: WifiManager.WifiLock? = null
  // Written on the main thread, read from the plugin bridge thread in setTrafficActive().
  @Volatile
  private var systemRestartPending: Boolean = false

  override fun onCreate() {
    super.onCreate()
    Log.i(TAG, "foreground service onCreate")
    createNotificationChannel()
    instance = this
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    val systemRestart = intent == null
    if (systemRestart) {
      systemRestartPending = true
      restoreInProgress = true
      restoreError = null
      Log.w(
        TAG,
        "foreground service restarted by Android without an intent; scheduling Rust runtime restore"
      )
    } else {
      systemRestartPending = false
      restoreInProgress = false
      restoreError = null
    }
    Log.i(
      TAG,
      "foreground service onStartCommand startId=$startId flags=$flags systemRestartPending=$systemRestartPending"
    )
    val notification = buildNotification()
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
      startForeground(
        NOTIFICATION_ID,
        notification,
        ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
      )
    } else {
      startForeground(NOTIFICATION_ID, notification)
    }

    // Locks are no longer held for the whole service lifetime. They follow
    // proxy traffic so the device can sleep while the proxy is idle.
    applyTrafficLocks(trafficActive && !systemRestartPending)
    updateRunning(
      true,
      systemRestartPending,
      wakeLock?.isHeld == true,
      wifiLock?.isHeld == true
    )

    if (systemRestart) {
      scheduleRuntimeRestore()
    } else {
      Log.i(TAG, "foreground service is running")
    }
    return START_STICKY
  }

  private fun scheduleRuntimeRestore() {
    val dataDir = applicationContext.dataDir.absolutePath
    val marker = File(dataDir, RESUME_MARKER_FILE)
    if (!marker.isFile) {
      restoreInProgress = false
      restoreError = "Automatic resume marker is missing; open Rama Proxy to start the proxy again"
      systemRestartPending = true
      updateRunning(
        true,
        true,
        wakeLock?.isHeld == true,
        wifiLock?.isHeld == true
      )
      updateNotificationIfNeeded()
      Log.w(TAG, "automatic resume marker is missing at ${marker.absolutePath}")
      return
    }

    restoreInProgress = true
    restoreError = null
    val scheduled = try {
      ensureNativeLoaded() && nativeRuntimeBridge(dataDir, true)
    } catch (error: Throwable) {
      restoreError = "Unable to schedule native runtime restore: ${error.message}"
      false
    }

    if (!scheduled) {
      restoreInProgress = false
      systemRestartPending = true
      if (restoreError == null) {
        restoreError = "Unable to schedule native runtime restore"
      }
      updateRunning(
        true,
        true,
        wakeLock?.isHeld == true,
        wifiLock?.isHeld == true
      )
      updateNotificationIfNeeded()
      Log.w(TAG, restoreError ?: "Unable to schedule native runtime restore")
    }
  }

  @Synchronized
  private fun ensureNativeLoaded(): Boolean {
    if (nativeLoaded) return true
    return try {
      System.loadLibrary("rama_proxy_mobile_lib")
      nativeLoaded = true
      true
    } catch (error: Throwable) {
      restoreError = "Unable to load native runtime: ${error.message}"
      Log.e(TAG, "failed to load native runtime", error)
      false
    }
  }

  private fun updateNotificationIfNeeded() {
    val manager = getSystemService(NotificationManager::class.java)
    manager.notify(NOTIFICATION_ID, buildNotification())
  }

  @Synchronized
  private fun applyTrafficLocks(active: Boolean) {
    if (active) {
      val lock = wakeLock ?: (getSystemService(POWER_SERVICE) as PowerManager)
        .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "$packageName:rama-proxy")
        .apply { setReferenceCounted(false) }
        .also { wakeLock = it }
      val wasHeld = lock.isHeld
      // Re-acquiring a non reference counted lock resets the safety timeout.
      lock.acquire(WAKE_LOCK_TIMEOUT_MS)
      if (!wasHeld) Log.i(TAG, "partial wake lock acquired for proxy traffic")

      if (wifiLock == null) {
        val wifiManager = applicationContext.getSystemService(WIFI_SERVICE) as? WifiManager
        wifiLock = wifiManager
          ?.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "$packageName:rama-proxy-wifi")
          ?.apply { setReferenceCounted(false) }
      }
      wifiLock?.let { wifi ->
        if (!wifi.isHeld) {
          wifi.acquire()
          Log.i(TAG, "high performance wifi lock acquired for proxy traffic")
        }
      }
    } else {
      wakeLock?.let { lock ->
        if (lock.isHeld) {
          lock.release()
          Log.i(TAG, "partial wake lock released; proxy is idle")
        }
      }
      wifiLock?.let { wifi ->
        if (wifi.isHeld) {
          wifi.release()
          Log.i(TAG, "high performance wifi lock released; proxy is idle")
        }
      }
    }
    // Only lock flags here; service running/restart state is owned by onStartCommand/onDestroy.
    wakeLockActive = wakeLock?.isHeld == true
    wifiLockActive = wifiLock?.isHeld == true
  }

  override fun onDestroy() {
    instance = null
    trafficActive = false
    restoreInProgress = false
    applyTrafficLocks(false)
    updateRunning(false, false, false, false)
    Log.i(TAG, "foreground service onDestroy")
    wakeLock = null
    wifiLock = null
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
      stopForeground(STOP_FOREGROUND_REMOVE)
    } else {
      @Suppress("DEPRECATION")
      stopForeground(true)
    }
    super.onDestroy()
  }

  override fun onBind(intent: Intent?): IBinder? = null

  private fun createNotificationChannel() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
    val manager = getSystemService(NotificationManager::class.java)
    val channel = NotificationChannel(
      CHANNEL_ID,
      "Rama Proxy",
      NotificationManager.IMPORTANCE_LOW
    ).apply {
      description = "Keeps the local SOCKS5 proxy running"
      setShowBadge(false)
    }
    manager.createNotificationChannel(channel)
  }

  private fun buildNotification(): Notification {
    val launchIntent = Intent(this, MainActivity::class.java).apply {
      flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
    }
    val pendingIntent = PendingIntent.getActivity(
      this,
      0,
      launchIntent,
      PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
    )

    val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      Notification.Builder(this, CHANNEL_ID)
    } else {
      Notification.Builder(this)
    }

    val title = when {
      restoreInProgress -> "Rama Proxy is restoring"
      systemRestartPending -> "Rama Proxy needs to be reopened"
      else -> "Rama Proxy is running"
    }
    val content = when {
      restoreInProgress -> "Restoring the local SOCKS5 listener automatically"
      systemRestartPending -> {
        restoreError
          ?: "Android restarted the service; open the app to restore the local SOCKS5 proxy"
      }
      else -> "Local SOCKS5 service is active; device sleep is allowed while idle"
    }

    return builder
      .setSmallIcon(R.mipmap.ic_launcher)
      .setContentTitle(title)
      .setContentText(content)
      .setContentIntent(pendingIntent)
      .setCategory(Notification.CATEGORY_SERVICE)
      .setOnlyAlertOnce(true)
      .setOngoing(true)
      .build()
  }

  companion object {
    private const val TAG = "RamaProxy"
    private const val CHANNEL_ID = "rama_proxy_local_socks5"
    private const val NOTIFICATION_ID = 2001
    private const val RESUME_MARKER_FILE = "resume.intent"
    // Safety net: Rust refreshes the lock well before this while traffic continues.
    private const val WAKE_LOCK_TIMEOUT_MS = 10 * 60 * 1000L

    @Volatile
    private var instance: ProxyForegroundService? = null

    @Volatile
    private var trafficActive: Boolean = false

    @Volatile
    private var nativeLoaded: Boolean = false

    @Volatile
    private var restoreInProgress: Boolean = false

    @Volatile
    private var restoreError: String? = null

    /** Called by the plugin when Rust reports proxy traffic starting or stopping. */
    fun setTrafficActive(active: Boolean) {
      trafficActive = active
      instance?.let { service ->
        service.applyTrafficLocks(active && !service.systemRestartPending)
      }
    }

    @JvmStatic
    fun setTrafficActiveFromRust(active: Boolean) {
      setTrafficActive(active)
    }

    @JvmStatic
    fun onRuntimeStoppedFromRust() {
      trafficActive = false
      val service = instance
      if (service == null) {
        updateRunning(false, false, false, false)
        return
      }
      service.systemRestartPending = true
      service.applyTrafficLocks(false)
      updateRunning(
        true,
        true,
        service.wakeLock?.isHeld == true,
        service.wifiLock?.isHeld == true
      )
      service.updateNotificationIfNeeded()
    }

    @JvmStatic
    fun onRuntimeRestoreResultFromRust(success: Boolean, message: String) {
      restoreInProgress = false
      restoreError = if (success) null else message.ifBlank {
        "The local SOCKS5 listener could not be restored automatically"
      }

      val service = instance
      if (service == null) {
        updateRunning(false, false, false, false)
        return
      }

      service.systemRestartPending = !success
      if (!success) trafficActive = false
      service.applyTrafficLocks(trafficActive && !service.systemRestartPending)
      updateRunning(
        true,
        !success,
        service.wakeLock?.isHeld == true,
        service.wifiLock?.isHeld == true
      )
      service.updateNotificationIfNeeded()
    }

    @Volatile
    private var running: Boolean = false

    @Volatile
    private var restartedBySystem: Boolean = false

    @Volatile
    private var wakeLockActive: Boolean = false

    @Volatile
    private var wifiLockActive: Boolean = false

    val isRunning: Boolean
      get() = running

    val isSystemRestarted: Boolean
      get() = restartedBySystem

    val isWakeLockHeld: Boolean
      get() = wakeLockActive

    val isWifiLockHeld: Boolean
      get() = wifiLockActive

    val isRestoreInProgress: Boolean
      get() = restoreInProgress

    val restoreErrorMessage: String?
      get() = restoreError

    internal fun updateRunning(
      value: Boolean,
      systemRestarted: Boolean,
      wakeLockHeld: Boolean,
      wifiLockHeld: Boolean
    ) {
      running = value
      restartedBySystem = systemRestarted
      wakeLockActive = wakeLockHeld
      wifiLockActive = wifiLockHeld
    }
  }
}
