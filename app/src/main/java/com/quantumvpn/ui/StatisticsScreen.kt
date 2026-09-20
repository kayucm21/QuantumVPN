package com.quantumvpn.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.quantumvpn.vpn.VpnConnectionState
import com.quantumvpn.vpn.VpnSessionStats

/** Primary statistics tab: uses real VPN-session counters, not demo figures. */
@Composable
internal fun StatisticsScreen(
    contentPadding: PaddingValues,
    sessionStats: VpnSessionStats,
    vpnState: VpnConnectionState,
) {
    val download = sessionStats.downloadTotalBytes
    val upload = sessionStats.uploadTotalBytes
    val total = download + upload
    val status = if (vpnState is VpnConnectionState.Connected) "VPN подключён" else "Ожидание подключения"
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(CosmicTokens.Void)
            .padding(contentPadding)
            .padding(horizontal = 20.dp, vertical = 18.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("Статистика", style = MaterialTheme.typography.displaySmall, color = Color.White, fontWeight = FontWeight.Bold)
        Text("Ваш сетевой трафик · $status", color = CosmicTokens.OnVoidMuted, style = MaterialTheme.typography.bodyMedium)
        Surface(
            color = CosmicTokens.Card,
            shape = RoundedCornerShape(22.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(22.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("За текущий сеанс", color = CosmicTokens.OnVoidMuted)
                Text(formatBytes(total), color = Color.White, style = MaterialTheme.typography.displayMedium, fontWeight = FontWeight.Bold)
                Text("Суммарно получено и отправлено через VPN", color = CosmicTokens.OnVoidMuted, style = MaterialTheme.typography.bodySmall)
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            StatisticMetric("Получено", formatBytes(download), Icons.Default.Menu, Modifier.weight(1f))
            StatisticMetric("Отправлено", formatBytes(upload), Icons.Default.Menu, Modifier.weight(1f))
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            StatisticMetric("Ping", sessionStats.pingMillis?.let { "$it мс" } ?: "—", Icons.Default.Menu, Modifier.weight(1f))
            StatisticMetric("Реклама", "${sessionStats.adBlockedSessionTotal}", Icons.Default.Menu, Modifier.weight(1f))
        }
    }
}

@Composable
private fun StatisticMetric(title: String, value: String, icon: androidx.compose.ui.graphics.vector.ImageVector, modifier: Modifier) {
    Surface(color = CosmicTokens.Panel, shape = RoundedCornerShape(18.dp), modifier = modifier) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Icon(icon, contentDescription = null, tint = CosmicTokens.Orbit)
            Text(title, color = CosmicTokens.OnVoidMuted, style = MaterialTheme.typography.labelMedium)
            Text(value, color = Color.White, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        }
    }
}
