package com.quantumvpn.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.quantumvpn.MainActivity
import com.quantumvpn.R
import com.quantumvpn.importer.SubscriptionQuotaStore
import com.quantumvpn.importer.SubscriptionUserInfo
import kotlinx.coroutines.flow.first

object SubscriptionExpiryNotifier {
    private const val CHANNEL_ID = "subscription_expiry"
    private const val NOTIFICATION_ID = 4301
    private const val THREE_DAYS_SEC = 3 * 86_400L

    suspend fun checkAndNotify(
        context: Context,
        quotaStore: SubscriptionQuotaStore,
        profileNames: Map<String, String>,
    ) {
        val nowSec = System.currentTimeMillis() / 1000
        val expiring = quotaStore.byProfileId.first().mapNotNull { (profileId, info) ->
            val expire = info.expireEpochSeconds ?: return@mapNotNull null
            if (expire <= nowSec) return@mapNotNull null
            val left = expire - nowSec
            if (left > THREE_DAYS_SEC) return@mapNotNull null
            profileNames[profileId] to info
        }
        if (expiring.isEmpty()) return
        ensureChannel(context)
        val (name, info) = expiring.first()
        val text = info.summaryRu.ifBlank { "Подписка «$name» скоро истекает" }
        val intent = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn_notification)
            .setContentTitle("Подписка истекает")
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(intent)
            .setAutoCancel(true)
            .build()
        context.getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, notification)
    }

    private fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Подписки",
            NotificationManager.IMPORTANCE_DEFAULT,
        )
        context.getSystemService(NotificationManager::class.java)
            .createNotificationChannel(channel)
    }
}
