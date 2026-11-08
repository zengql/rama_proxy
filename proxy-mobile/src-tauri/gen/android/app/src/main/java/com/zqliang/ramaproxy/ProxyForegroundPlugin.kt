package com.zqliang.ramaproxy

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@TauriPlugin
class ProxyForegroundPlugin(private val activity: Activity) : Plugin(activity) {
  @Command
  fun start(invoke: Invoke) {
    try {
      if (
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
        activity.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
          PackageManager.PERMISSION_GRANTED
      ) {
        activity.requestPermissions(
          arrayOf(Manifest.permission.POST_NOTIFICATIONS),
          NOTIFICATION_PERMISSION_REQUEST
        )
      }

      val intent = Intent(activity, ProxyForegroundService::class.java)
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        activity.startForegroundService(intent)
      } else {
        activity.startService(intent)
      }
      invoke.resolve()
    } catch (error: Exception) {
      invoke.reject(error.message ?: "Failed to start foreground service")
    }
  }

  @Command
  fun stop(invoke: Invoke) {
    try {
      activity.stopService(Intent(activity, ProxyForegroundService::class.java))
      invoke.resolve()
    } catch (error: Exception) {
      invoke.reject(error.message ?: "Failed to stop foreground service")
    }
  }

  @Command
  fun status(invoke: Invoke) {
    try {
      val result = JSObject()
      result.put("running", ProxyForegroundService.isRunning)
      result.put("systemRestarted", ProxyForegroundService.isSystemRestarted)
      result.put("batteryOptimizationIgnored", isIgnoringBatteryOptimizations())
      result.put("wakeLockHeld", ProxyForegroundService.isWakeLockHeld)
      result.put("wifiLockHeld", ProxyForegroundService.isWifiLockHeld)
      invoke.resolve(result)
    } catch (error: Exception) {
      invoke.reject(error.message ?: "Failed to query foreground service status")
    }
  }

  @Command
  fun requestBatteryOptimizationExemption(invoke: Invoke) {
    try {
      val requestIntent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
        data = Uri.parse("package:${activity.packageName}")
      }
      try {
        activity.startActivity(requestIntent)
      } catch (_: Exception) {
        activity.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
      }
      invoke.resolve()
    } catch (error: Exception) {
      invoke.reject(error.message ?: "Failed to open battery optimization settings")
    }
  }

  private fun isIgnoringBatteryOptimizations(): Boolean {
    val powerManager = activity.getSystemService(Activity.POWER_SERVICE) as PowerManager
    return powerManager.isIgnoringBatteryOptimizations(activity.packageName)
  }

  private companion object {
    const val NOTIFICATION_PERMISSION_REQUEST = 3107
  }
}
