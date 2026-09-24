package com.quantumvpn.vpn

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.SystemClock
import com.quantumvpn.BuildConfig
import com.quantumvpn.QuantumVpnApplication
import com.quantumvpn.updates.UpdateChannel
import kotlinx.coroutines.runBlocking

/**
 * Periodic update checks while the app is not open.
 * Uses [UpdateController.check] (not checkOnce) so every alarm can surface Available
 * and post a system notification without waiting for MainActivity.
 */
object UpdateCheckAlarms {
    const val ACTION = "com.quantumvpn.action.CHECK_UPDATES"
    /** Background probe; never interrupt an active splash/download. */
    const val INTERVAL_MS = 120L * 1000L
    const val FIRST_DELAY_MS = 60L * 1000L

    fun reschedule(context: Context) {
        val am = context.getSystemService(AlarmManager::class.java) ?: return
        val pi = pendingIntent(context)
        am.cancel(pi)
        val triggerAt = SystemClock.elapsedRealtime() + FIRST_DELAY_MS
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerAt, pi)
        } else {
            am.set(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerAt, pi)
        }
    }

    fun rescheduleNext(context: Context) {
        val am = context.getSystemService(AlarmManager::class.java) ?: return
        val pi = pendingIntent(context)
        val triggerAt = SystemClock.elapsedRealtime() + INTERVAL_MS
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerAt, pi)
        } else {
            am.set(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerAt, pi)
        }
    }

    private fun pendingIntent(context: Context): PendingIntent =
        PendingIntent.getBroadcast(
            context,
            41,
            Intent(ACTION).setPackage(context.packageName),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
}

class UpdateCheckReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != UpdateCheckAlarms.ACTION) return
        val app = context.applicationContext as? QuantumVpnApplication ?: return
        val pending = goAsync()
        Thread {
            try {
                runBlocking {
                    when (app.container.updateController.state.value) {
                        is com.quantumvpn.updates.UpdateState.Downloading,
                        is com.quantumvpn.updates.UpdateState.Ready,
                        is com.quantumvpn.updates.UpdateState.Checking,
                        is com.quantumvpn.updates.UpdateState.RetryingViaVpn -> return@runBlocking
                        else -> Unit
                    }
                    val policy = app.container.clientPolicyRepository.refresh()
                    // Prefer panel version signal for an immediate notification even before APK probe.
                    if (policy != null &&
                        policy.versionCode > BuildConfig.VERSION_CODE &&
                        policy.latestVersion.isNotBlank()
                    ) {
                        val prefs = app.getSharedPreferences("update_notifications", android.content.Context.MODE_PRIVATE)
                        val version = policy.latestVersion
                        if (prefs.getString("last_version", "") != version) {
                            app.container.notificationManager.showUpdateAvailableNotification(version)
                            prefs.edit().putString("last_version", version).apply()
                        }
                        // Only auto-download from alarm when app UI is not already handling it.
                        app.container.updateController.check(UpdateChannel.Stable, autoDownload = false)
                    } else {
                        app.container.updateController.check(UpdateChannel.Stable, autoDownload = false)
                    }
                }
            } finally {
                UpdateCheckAlarms.rescheduleNext(app)
                pending.finish()
            }
        }.start()
    }
}
