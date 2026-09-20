package com.quantumvpn.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Re-arms periodic alarms after a device reboot so subscription auto-refresh
 * (and schedule alarms) stay always-on without requiring the user to open the app.
 */
class SubscriptionRefreshBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return
        val ctx = context.applicationContext
        SubscriptionRefreshAlarms.reschedule(ctx)
        VpnScheduleAlarms.reschedule(ctx)
    }
}