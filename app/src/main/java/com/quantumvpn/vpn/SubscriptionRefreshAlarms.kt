package com.quantumvpn.vpn

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.quantumvpn.QuantumVpnApplication
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import com.quantumvpn.updates.UpdateChannel

/**
 * Always-on periodic subscription refresh (no manual action required).
 * Default interval 6 hours; never disabled by settings.
 */
object SubscriptionRefreshAlarms {
    const val ACTION = "com.quantumvpn.action.REFRESH_SUBSCRIPTIONS"
    const val DEFAULT_HOURS = 1
    /** Pending flag for next ProfilesViewModel tick when receiver can't refresh fully. */
    @Volatile
    var pendingRefresh: Boolean = false

    fun reschedule(context: Context) {
        val app = context.applicationContext as? QuantumVpnApplication ?: return
        val configured = runBlocking {
            app.container.uiSettingsStore.settings.first().subscriptionRefreshHours
        }
        val hours = if (configured <= 0) DEFAULT_HOURS else configured.coerceAtMost(24)
        val am = context.getSystemService(AlarmManager::class.java)
        val pi = PendingIntent.getBroadcast(
            context,
            40,
            Intent(ACTION).setPackage(context.packageName),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        am.cancel(pi)
        val interval = hours * AlarmManager.INTERVAL_HOUR
        am.setInexactRepeating(
            AlarmManager.RTC_WAKEUP,
            System.currentTimeMillis() + interval,
            interval,
            pi,
        )
    }
}

class SubscriptionRefreshReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != SubscriptionRefreshAlarms.ACTION) return
        val app = context.applicationContext as? QuantumVpnApplication ?: return
        SubscriptionRefreshAlarms.pendingRefresh = true
        runCatching {
            val pending = goAsync()
            Thread {
                try {
                    runBlocking {
                        app.container.clientPolicyRepository.refresh()
                        when (app.container.updateController.state.value) {
                            is com.quantumvpn.updates.UpdateState.Downloading,
                            is com.quantumvpn.updates.UpdateState.Ready,
                            is com.quantumvpn.updates.UpdateState.Checking,
                            is com.quantumvpn.updates.UpdateState.RetryingViaVpn -> Unit
                            else -> {
                                // Background: always re-check (not checkOnce) so update alerts fire without opening UI.
                                app.container.updateController.check(UpdateChannel.Stable, autoDownload = false)
                            }
                        }
                        app.container.eventJournalStore.append(
                            "subs",
                            "Scheduled subscription refresh requested",
                        )
                    }
                } finally {
                    pending.finish()
                }
            }.start()
        }
    }
}
