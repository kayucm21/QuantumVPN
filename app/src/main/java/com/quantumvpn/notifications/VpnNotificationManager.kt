package com.quantumvpn.notifications

import android.content.Context
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

/**
 * Управление уведомлениями о проблемах и падении VPN
 */
class VpnNotificationManager(
    private val context: Context,
    private val dataStore: DataStore<Preferences>
) {
    companion object {
        private val NOTIFICATIONS_ENABLED_KEY = booleanPreferencesKey("notifications_enabled")
        private val CRITICAL_ALERTS_KEY = booleanPreferencesKey("critical_alerts_enabled")
        
        private const val CHANNEL_ID_CRITICAL = "vpn_critical_alerts"
        private const val CHANNEL_ID_INFO = "vpn_info_notifications"
        private const val NOTIFICATION_ID_CRITICAL = 1001
        private const val NOTIFICATION_ID_RECONNECT = 1002
        private const val NOTIFICATION_ID_DISCONNECTED = 1003
    }

    private val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    init {
        createNotificationChannels()
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            // Критические оповещения
            val criticalChannel = NotificationChannel(
                CHANNEL_ID_CRITICAL,
                "Критические оповещения VPN",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Важные уведомления о проблемах VPN"
            }
            
            // Информационные уведомления
            val infoChannel = NotificationChannel(
                CHANNEL_ID_INFO,
                "Информация VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Обычные уведомления о статусе VPN"
            }
            
            notificationManager.createNotificationChannel(criticalChannel)
            notificationManager.createNotificationChannel(infoChannel)
        }
    }

    fun isNotificationsEnabled(): Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[NOTIFICATIONS_ENABLED_KEY] ?: true
    }

    suspend fun setNotificationsEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[NOTIFICATIONS_ENABLED_KEY] = enabled
        }
    }

    fun isCriticalAlertsEnabled(): Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[CRITICAL_ALERTS_KEY] ?: true
    }

    suspend fun setCriticalAlertsEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[CRITICAL_ALERTS_KEY] = enabled
        }
    }

    /**
     * Уведомление о падении VPN
     */
    fun showVpnDisconnectedNotification() {
        val notification = NotificationCompat.Builder(context, CHANNEL_ID_CRITICAL)
            .setContentTitle("VPN отключено")
            .setContentText("Соединение потеряно. Попытка переподключения...")
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()

        notificationManager.notify(NOTIFICATION_ID_DISCONNECTED, notification)
    }

    /**
     * Уведомление об автопереподключении
     */
    fun showReconnectingNotification(attempt: Int, maxAttempts: Int) {
        val notification = NotificationCompat.Builder(context, CHANNEL_ID_INFO)
            .setContentTitle("Переподключение VPN")
            .setContentText("Попытка $attempt из $maxAttempts...")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setProgress(maxAttempts, attempt, false)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()

        notificationManager.notify(NOTIFICATION_ID_RECONNECT, notification)
    }

    /**
     * Уведомление об ошибке подключения
     */
    fun showConnectionErrorNotification(errorMessage: String) {
        val notification = NotificationCompat.Builder(context, CHANNEL_ID_CRITICAL)
            .setContentTitle("Ошибка подключения VPN")
            .setContentText(errorMessage)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()

        notificationManager.notify(NOTIFICATION_ID_CRITICAL, notification)
    }

    /**
     * Очистить уведомления
     */
    fun dismissNotifications() {
        notificationManager.cancel(NOTIFICATION_ID_CRITICAL)
        notificationManager.cancel(NOTIFICATION_ID_RECONNECT)
        notificationManager.cancel(NOTIFICATION_ID_DISCONNECTED)
    }
}
