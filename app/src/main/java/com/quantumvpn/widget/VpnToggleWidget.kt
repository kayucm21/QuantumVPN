package com.quantumvpn.widget

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.Context
import android.content.Intent
import android.view.View
import android.widget.RemoteViews
import com.quantumvpn.MainActivity
import com.quantumvpn.R
import com.quantumvpn.QuantumVpnApplication
import com.quantumvpn.vpn.VpnConnectionState

class VpnToggleWidget : AppWidgetProvider() {
    override fun onUpdate(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetIds: IntArray,
    ) {
        val app = context.applicationContext as? QuantumVpnApplication
        val state = runCatching { app?.container?.vpnController?.state?.value }.getOrNull()
        val stats = runCatching { app?.container?.vpnController?.sessionStats?.value }.getOrNull()
        val connected = state is VpnConnectionState.Connected
        val flag = when {
            connected && stats?.exitFlagEmoji != null -> stats.exitFlagEmoji
            connected -> "🛡"
            else -> "🌐"
        }
        val label = when (state) {
            is VpnConnectionState.Connected -> "Отключить"
            is VpnConnectionState.Starting, is VpnConnectionState.Stopping -> "…"
            else -> "Подключить"
        }
        val status = when (state) {
            is VpnConnectionState.Connected -> "Защищено"
            is VpnConnectionState.Starting -> "Подключение…"
            is VpnConnectionState.Stopping -> "Отключение…"
            is VpnConnectionState.Error -> "Ошибка"
            else -> "Не защищено"
        }
        val detail = when {
            connected && stats != null -> listOfNotNull(
                stats.exitLocation?.countryName ?: stats.exitLocation?.displayLabel,
                stats.pingMillis?.let { "$it ms" },
                stats.connectedAtEpochMillis?.let { started ->
                    val sec = ((System.currentTimeMillis() - started).coerceAtLeast(0L) / 1000L)
                    "%d:%02d".format(sec / 60, sec % 60)
                },
            ).joinToString(" · ").ifBlank { stats.externalIp.orEmpty() }
            else -> ""
        }
        for (id in appWidgetIds) {
            val views = RemoteViews(context.packageName, R.layout.widget_vpn_toggle)
            views.setTextViewText(R.id.widget_flag, flag)
            views.setTextViewText(R.id.widget_status, status)
            views.setTextViewText(R.id.widget_detail, detail)
            val traffic = if (connected && stats != null) {
                "↓ ${formatWidgetBytes(stats.downloadTotalBytes)}  ↑ ${formatWidgetBytes(stats.uploadTotalBytes)}"
            } else {
                ""
            }
            views.setTextViewText(R.id.widget_traffic, traffic)
            views.setViewVisibility(
                R.id.widget_detail,
                if (detail.isBlank()) View.GONE else View.VISIBLE,
            )
            views.setViewVisibility(
                R.id.widget_traffic,
                if (traffic.isBlank()) View.GONE else View.VISIBLE,
            )
            views.setTextViewText(R.id.widget_action, label)
            val open = PendingIntent.getActivity(
                context,
                id,
                Intent(context, MainActivity::class.java).putExtra(EXTRA_WIDGET_TOGGLE, true),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            views.setOnClickPendingIntent(R.id.widget_root, open)
            views.setOnClickPendingIntent(R.id.widget_action, open)
            appWidgetManager.updateAppWidget(id, views)
        }
    }

    companion object {
        const val EXTRA_WIDGET_TOGGLE = "com.quantumvpn.widget.TOGGLE"

        fun requestUpdate(context: Context) {
            val intent = Intent(context, VpnToggleWidget::class.java)
                .setAction(AppWidgetManager.ACTION_APPWIDGET_UPDATE)
            val ids = AppWidgetManager.getInstance(context)
                .getAppWidgetIds(android.content.ComponentName(context, VpnToggleWidget::class.java))
            intent.putExtra(AppWidgetManager.EXTRA_APPWIDGET_IDS, ids)
            context.sendBroadcast(intent)
        }

        private fun formatWidgetBytes(value: Long): String = when {
            value < 1024 -> "$value B"
            value < 1024 * 1024 -> "%.0fK".format(value / 1024.0)
            value < 1024L * 1024 * 1024 -> "%.1fM".format(value / (1024.0 * 1024))
            else -> "%.1fG".format(value / (1024.0 * 1024 * 1024))
        }
    }
}
