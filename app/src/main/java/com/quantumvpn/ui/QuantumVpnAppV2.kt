package com.quantumvpn.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.TextButton
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.geometry.Offset
import com.quantumvpn.updates.UpdateState
import com.quantumvpn.BuildConfig
import com.quantumvpn.QuantumVpnApplication
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.platform.LocalContext
import kotlinx.coroutines.launch
import com.quantumvpn.diagnostics.DiagnosticState
import com.quantumvpn.diagnostics.SessionTrafficRecord
import com.quantumvpn.diagnostics.VoluntaryDiagnosticReporter
import com.quantumvpn.donations.DonationEntry
import com.quantumvpn.donations.DonationRepository
import com.quantumvpn.donations.DonationSummary
import com.quantumvpn.profiles.ProfilesUiState
import com.quantumvpn.profiles.ProfilesViewModel
import com.quantumvpn.vpn.RuntimeSelectorGroup
import com.quantumvpn.vpn.VpnConnectionState
import com.quantumvpn.vpn.VpnSessionStats
import com.quantumvpn.vpn.ServerHealthScore
import com.quantumvpn.vpn.DeadServerQuarantineStore
import com.quantumvpn.vpn.forServerUi
import com.quantumvpn.vpn.primaryGroup
import com.quantumvpn.vpn.UnderlyingServerPing
import com.quantumvpn.vpn.ServerSwitchEvent
import com.quantumvpn.policy.ClientPolicy

private enum class V2Tab(val title: String, val icon: ImageVector) {
    Home("Главная", Icons.Default.Home),
    Servers("Серверы", Icons.AutoMirrored.Filled.List),
    Statistics("Статистика", Icons.Default.Menu),
    Settings("Настройки", Icons.Default.Settings),
}

/** Liquid Glass Orbit — cyan/blue glassmorphism matching the design mockup. */
private val LocalAuroraDark = staticCompositionLocalOf { true }
private val LocalAuroraAccent = staticCompositionLocalOf { Color(0xFF3DE7FF) }
private object Aurora {
    val Night: Color @Composable get() = if (LocalAuroraDark.current) Color(0xFF040B16) else Color(0xFFF3F7FB)
    val VioletNight: Color @Composable get() = if (LocalAuroraDark.current) Color(0xFF071526) else Color(0xFFE8F1FA)
    val Glass: Color @Composable get() = if (LocalAuroraDark.current) Color(0xCC0B1E33) else Color(0xE6FFFFFF)
    val Mint: Color @Composable get() = if (LocalAuroraDark.current) LocalAuroraAccent.current else Color(0xFF0087A8)
    val Violet: Color @Composable get() = if (LocalAuroraDark.current) Color(0xFF2A7BFF) else Color(0xFF2563EB)
    val Text: Color @Composable get() = if (LocalAuroraDark.current) Color(0xFFF4FBFF) else Color(0xFF0B1A2A)
    val Muted: Color @Composable get() = if (LocalAuroraDark.current) Color(0xFF8FA9BE) else Color(0xFF51657A)
    val Border: Color @Composable get() = if (LocalAuroraDark.current) Color(0xFF1E4C6B) else Color(0xFFB7CDDE)
    val Danger: Color @Composable get() = Color(0xFFFF7A93)
}

private fun remoteAccent(value: String): Color = runCatching {
    Color(android.graphics.Color.parseColor(value))
}.getOrDefault(Color(0xFF3DE7FF))

/** The production visual shell. It replaces the legacy hub without touching VPN core. */
@Composable
fun QuantumVpnAppV2(
    state: ProfilesUiState,
    viewModel: ProfilesViewModel,
    vpnState: VpnConnectionState,
    selectorGroups: List<RuntimeSelectorGroup>,
    sessionStats: VpnSessionStats,
    diagnostics: DiagnosticState,
    onVpnStart: (String) -> Unit,
    onVpnStop: () -> Unit,
    onSelectServer: (String, String) -> Unit,
    onHomeSelected: (Boolean) -> Unit,
    onMeasurePing: () -> Unit,
    onMeasureGroup: (String) -> Unit,
    updateState: UpdateState,
    onCheckUpdate: () -> Unit,
    onDownloadUpdate: () -> Unit,
    onInstallUpdate: () -> Unit,
    onCancelUpdate: () -> Unit,
) {
    var tab by rememberSaveable { mutableStateOf(V2Tab.Home) }
    androidx.compose.runtime.DisposableEffect(tab) {
        onHomeSelected(tab == V2Tab.Home || tab == V2Tab.Statistics)
        onDispose { onHomeSelected(false) }
    }
    LaunchedEffect(state.message) {
        if (state.message != null) {
            kotlinx.coroutines.delay(2_600)
            viewModel.consumeMessage()
        }
    }
    val groups = selectorGroups.forServerUi()
    val mainGroup = groups.primaryGroup()
    val selected = mainGroup?.items?.firstOrNull { it.tag == mainGroup.selected } ?: mainGroup?.items?.firstOrNull()
    val activeProfile = state.profiles.firstOrNull { it.id == state.settings.activeProfileId } ?: state.profiles.firstOrNull()
    val connected = vpnState is VpnConnectionState.Connected
    val busy = vpnState is VpnConnectionState.Starting || vpnState is VpnConnectionState.Stopping
    var lastConnectedStats by remember { mutableStateOf<VpnSessionStats?>(null) }
    LaunchedEffect(connected, sessionStats) {
        if (connected) {
            lastConnectedStats = sessionStats
        } else {
            lastConnectedStats?.let { finished ->
                val durationSec = finished.connectedAtEpochMillis
                    ?.let { ((System.currentTimeMillis() - it) / 1000L).coerceAtLeast(0L) }
                    ?: 0L
                viewModel.recordSessionTraffic(
                    profileName = activeProfile?.name ?: "QuantumVPN",
                    downloadBytes = finished.downloadTotalBytes,
                    uploadBytes = finished.uploadTotalBytes,
                    durationSec = durationSec,
                )
            }
            lastConnectedStats = null
        }
    }
    val context = LocalContext.current
    var offlinePings by remember { mutableStateOf<Map<String, Int>>(emptyMap()) }
    val pingItems = remember(groups) { groups.flatMap { it.items }.distinctBy { it.tag } }
    LaunchedEffect(pingItems) {
        while (true) {
            offlinePings = UnderlyingServerPing.measure(context, pingItems)
            kotlinx.coroutines.delay(20_000)
        }
    }
    LaunchedEffect(tab, connected, mainGroup?.tag) {
        if (!connected) return@LaunchedEffect
        while (tab == V2Tab.Servers || tab == V2Tab.Home) {
            mainGroup?.tag?.takeIf(String::isNotBlank)?.let(onMeasureGroup) ?: onMeasurePing()
            kotlinx.coroutines.delay(20_000)
        }
    }
    val app = context.applicationContext as QuantumVpnApplication
    val policy by app.container.clientPolicyRepository.policy.collectAsState()
    val trafficHistory by viewModel.sessionTrafficHistory.collectAsState()
    val switchHistory by viewModel.switchHistory.collectAsState()
    val reliabilityScores by viewModel.reliabilityScores.collectAsState()
    val privacyScore = PrivacyScore.calculate(
        vpnConnected = connected,
        adBlockEnabled = state.settings.adBlockEnabled,
        killSwitchEnabled = state.settings.blockNonVpnTraffic,
        secureDnsEnabled = state.settings.adBlockOnlineDns || state.settings.dnsMode != com.quantumvpn.config.DnsMode.FromJson,
        autoFailoverEnabled = state.settings.autoFailoverEnabled,
        unknownWifiProtection = state.settings.protectUnknownWifi,
    )
    val block = policy.blockReason(BuildConfig.VERSION_CODE.toLong())
    LaunchedEffect(block, connected) {
        if (block != null && connected) onVpnStop()
    }
    val dark = when (state.settings.themeMode) {
        ThemeMode.System -> isSystemInDarkTheme()
        ThemeMode.Dark -> true
        ThemeMode.Light -> false
    }
    val adaptiveAccent = if (state.settings.useDynamicColor) {
        MaterialTheme.colorScheme.primary
    } else {
        remoteAccent(policy.branding.accentHex)
    }
    CompositionLocalProvider(LocalAuroraDark provides dark, LocalAuroraAccent provides adaptiveAccent) {
    Surface(color = Aurora.Night, modifier = Modifier.fillMaxSize().safeDrawingPadding()) {
        if (policy.maintenance) {
            V2MaintenanceScreen(policy.maintenanceMessage)
            return@Surface
        }
        Column(Modifier.fillMaxSize()) {
            if (block != null || policy.activeAnnounce().isNotBlank()) {
                Text(block ?: policy.activeAnnounce(), color = Aurora.Text, modifier = Modifier.fillMaxWidth().background(Aurora.Glass).padding(16.dp))
            }
            if (state.message != null) Text(state.message, color = Aurora.Muted, modifier = Modifier.padding(horizontal = 16.dp))
            Box(Modifier.weight(1f)) {
                when (tab) {
                    V2Tab.Home -> V2Home(
                        policy = policy,
                        connected = connected,
                        busy = busy,
                        hasProfile = activeProfile != null,
                        server = selected?.tag ?: "Автоматический сервер",
                        ping = selected?.pingMillis ?: selected?.tag?.let(offlinePings::get),
                        adBlock = state.settings.adBlockEnabled,
                        privacyScore = privacyScore,
                        stats = sessionStats,
                        onConnect = {
                            val id = activeProfile?.id
                            if (id == null) viewModel.installManagedSubscription()
                            else if (connected) onVpnStop()
                            else if (block == null && !busy) onVpnStart(id)
                        },
                        onServers = { tab = V2Tab.Servers },
                        onSettings = { tab = V2Tab.Settings },
                    )
                    V2Tab.Servers -> V2Servers(groups, mainGroup?.tag, mainGroup?.selected, offlinePings, onSelectServer, activeProfile?.id, reliabilityScores, activeProfile?.updatedAtEpochMillis, state.busy) { viewModel.refreshAllSubscriptionsQuietly() }
                    V2Tab.Statistics -> V2Statistics(
                        stats = sessionStats,
                        connected = connected,
                        history = trafficHistory,
                        switchHistory = switchHistory,
                        diagnostics = diagnostics,
                        cumulativeBlocked = state.settings.cumulativeBlocked,
                    )
                    V2Tab.Settings -> V2Settings(
                        diagnostics = diagnostics,
                        policy = policy,
                        theme = state.settings.themeMode,
                        dynamicColor = state.settings.useDynamicColor,
                        autoConnect = state.settings.autoConnectOnCellular,
                        notifications = !state.settings.quietMode,
                        protectUnknownWifi = state.settings.protectUnknownWifi,
                        travelMode = state.settings.travelModeEnabled,
                        onTheme = viewModel::setTheme,
                        onDynamicColor = viewModel::setUseDynamicColor,
                        onAutoConnect = viewModel::setAutoConnectOnCellular,
                        onNotifications = { enabled -> viewModel.setQuietMode(!enabled) },
                        onProtectUnknownWifi = viewModel::setProtectUnknownWifi,
                        onTravelMode = viewModel::setTravelModeEnabled,
                        adBlock = state.settings.adBlockEnabled,
                        killSwitch = state.settings.blockNonVpnTraffic,
                        onAdBlock = viewModel::setAdBlockEnabled,
                        onKillSwitch = viewModel::setBlockNonVpnTraffic,
                    )
                }
            }
            V2BottomBar(tab = tab, onTab = { tab = it })
        }
    }
    // Обновление проверяется и скачивается на сплэше до открытия интерфейса.
    when (val update = updateState) {
        is UpdateState.Ready -> UpdateReadyDialog(update.candidate, onInstallUpdate, onCancelUpdate)
        is UpdateState.Failure -> {
            val ctx = androidx.compose.ui.platform.LocalContext.current
            AlertDialog(
                onDismissRequest = onCancelUpdate,
                title = { Text("Обновление") },
                text = {
                    Text(
                        (update.message.ifBlank { "Не удалось загрузить в приложении." }) +
                            "\n\nОткройте загрузку в браузере — Android сам предложит установить APK.",
                    )
                },
                confirmButton = {
                    TextButton(onClick = {
                        val url = update.candidate?.apkAsset?.downloadUrl
                            ?: "https://tepacom.o190.com:8443/update"
                        runCatching {
                            ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                        }
                    }) { Text("Скачать в браузере") }
                },
                dismissButton = {
                    TextButton(onClick = onCheckUpdate) { Text("Повторить") }
                },
            )
        }
        else -> Unit
    }
    }
}

@Composable
private fun V2MaintenanceScreen(message: String) {
    Box(
        Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Aurora.VioletNight, Aurora.Night))),
        contentAlignment = Alignment.Center,
    ) {
        Column(Modifier.padding(30.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Surface(
                shape = CircleShape,
                color = Aurora.Mint.copy(alpha = .10f),
                border = androidx.compose.foundation.BorderStroke(2.dp, Aurora.Mint.copy(alpha = .65f)),
                modifier = Modifier.size(116.dp),
            ) { Box(contentAlignment = Alignment.Center) { Icon(Icons.Default.Settings, null, tint = Aurora.Mint, modifier = Modifier.size(54.dp)) } }
            Spacer(Modifier.height(24.dp))
            Text("Ведутся технические работы", color = Aurora.Text, fontSize = 27.sp, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center)
            Text(
                message.ifBlank { "После завершения работ мы автоматически возобновим сервис." },
                color = Aurora.Muted,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 12.dp),
            )
            Text("Проверяем состояние сервиса автоматически", color = Aurora.Mint, fontSize = 12.sp, modifier = Modifier.padding(top = 24.dp))
        }
    }
}

private fun serverFlag(name: String): String {
    val value = name.lowercase()
    return when {
        "рос" in value || "moscow" in value -> "🇷🇺"
        "нидер" in value || "amsterdam" in value -> "🇳🇱"
        "герман" in value || "frankfurt" in value -> "🇩🇪"
        "сингап" in value || "singapore" in value -> "🇸🇬"
        "сша" in value || "usa" in value || "new york" in value -> "🇺🇸"
        "британ" in value || "london" in value -> "🇬🇧"
        "япон" in value || "tokyo" in value -> "🇯🇵"
        "финл" in value || "helsinki" in value -> "🇫🇮"
        else -> "🌐"
    }
}

private fun serverRegion(name: String): String {
    val value = name.lowercase()
    return when {
        listOf("usa", "сша", "new york", "america", "canada", "бразил", "mexico").any { it in value } -> "Америка"
        listOf("сингап", "singapore", "япон", "tokyo", "korea", "hong", "taiwan", "india", "азия").any { it in value } -> "Азия"
        else -> "Европа"
    }
}

@Composable
private fun V2Home(
    policy: ClientPolicy,
    connected: Boolean, busy: Boolean, hasProfile: Boolean, server: String, ping: Int?, adBlock: Boolean, privacyScore: Int, stats: VpnSessionStats,
    onConnect: () -> Unit, onServers: () -> Unit, onSettings: () -> Unit,
) {
    Box(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Color(0xFF05111F), Color(0xFF071A2C), Color(0xFF040B16))))) {
        Globe3DBackdrop(Modifier.fillMaxSize(), pulse = true, reduceMotion = false, countryCode = null)
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 18.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Row {
                        Text(policy.branding.name, color = Aurora.Text, fontSize = 24.sp, fontWeight = FontWeight.Bold)
                    }
                    Text(policy.branding.tagline, color = Aurora.Muted, fontSize = 10.sp, letterSpacing = 1.5.sp)
                }
                Surface(onClick = onSettings, shape = CircleShape, color = Aurora.Glass, border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border), modifier = Modifier.size(42.dp)) {
                    Box(contentAlignment = Alignment.Center) { Icon(Icons.Default.Settings, null, tint = Aurora.Mint) }
                }
            }
            Spacer(Modifier.height(14.dp))
            Surface(onClick = onServers, color = Aurora.Glass, border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Mint.copy(alpha = .35f)), shape = RoundedCornerShape(22.dp), modifier = Modifier.fillMaxWidth()) {
                Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("🌐", fontSize = 22.sp)
                    Column(Modifier.weight(1f).padding(start = 12.dp)) {
                        Text("Лучший сервер", color = Aurora.Text, fontWeight = FontWeight.SemiBold)
                        Text("Автовыбор · Низкий пинг", color = Aurora.Muted, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    Surface(color = Color(0xFF2EE59D).copy(alpha = .18f), shape = RoundedCornerShape(999.dp)) {
                        Text(ping?.let { "$it мс" } ?: "авто", color = Color(0xFF2EE59D), fontWeight = FontWeight.Bold, modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp))
                    }
                }
            }
            Spacer(Modifier.height(28.dp))
            Surface(
                shape = CircleShape,
                color = Aurora.Glass.copy(alpha = .55f),
                border = androidx.compose.foundation.BorderStroke(3.dp, if (connected) Aurora.Mint else Aurora.Violet.copy(alpha = .85f)),
                modifier = Modifier.size(196.dp).clickable(enabled = !busy) { onConnect() },
            ) {
                Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
                    Icon(if (connected) Icons.Default.CheckCircle else Icons.Default.Lock, null, tint = Aurora.Mint, modifier = Modifier.size(58.dp))
                    Spacer(Modifier.height(10.dp))
                    Text(if (connected) "Отключить" else if (busy) "Подключение…" else "Подключить", color = Aurora.Text, fontWeight = FontWeight.Bold, fontSize = 20.sp)
                }
            }
            Spacer(Modifier.height(18.dp))
            Text(
                if (connected) "Вы подключены" else "Вы не подключены",
                color = if (connected) Aurora.Mint else Aurora.Danger,
                fontWeight = FontWeight.Bold,
                fontSize = 20.sp,
            )
            Text(
                if (connected) "Ваша активность защищена" else "Ваша активность не защищена",
                color = Aurora.Muted,
                fontSize = 13.sp,
            )
            Spacer(Modifier.height(22.dp))
            Surface(
                color = Aurora.Glass,
                border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border),
                shape = RoundedCornerShape(22.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Row(
                    Modifier.fillMaxWidth().padding(vertical = 14.dp, horizontal = 8.dp),
                    horizontalArrangement = Arrangement.SpaceEvenly,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    V2HomeStat("📶", ping?.let { "$it мс" } ?: "—", "Пинг", Color(0xFF2EE59D))
                    V2HomeStat("↓", stats.samples.lastOrNull()?.let { formatBytes(it.downloadBytesPerSecond) + "/с" } ?: "—", "Загрузка", Aurora.Mint)
                    V2HomeStat("↑", stats.samples.lastOrNull()?.let { formatBytes(it.uploadBytesPerSecond) + "/с" } ?: "—", "Отдача", Aurora.Violet)
                }
            }
            if (adBlock) {
                Spacer(Modifier.height(12.dp))
                Text("DNS-фильтр активен после подключения", color = Aurora.Muted, fontSize = 12.sp)
            }
            Spacer(Modifier.height(12.dp))
            Surface(
                color = Aurora.Glass.copy(alpha = .9f),
                border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Mint.copy(alpha = .45f)),
                shape = RoundedCornerShape(18.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Индекс приватности", color = Aurora.Text, fontWeight = FontWeight.SemiBold)
                        Text(PrivacyScore.label(privacyScore), color = Aurora.Muted, fontSize = 12.sp)
                    }
                    Text("$privacyScore/100", color = Aurora.Mint, fontSize = 21.sp, fontWeight = FontWeight.Bold)
                }
            }
            if (!hasProfile) {
                Spacer(Modifier.height(10.dp))
                Text("Загружаем серверы…", color = Aurora.Mint, fontSize = 12.sp)
            }
        }
    }
}

@Composable
private fun V2HomeStat(icon: String, value: String, label: String, accent: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(horizontal = 6.dp)) {
        Text(icon, fontSize = 16.sp, color = accent)
        Text(value, color = Aurora.Text, fontWeight = FontWeight.Bold, fontSize = 16.sp)
        Text(label, color = Aurora.Muted, fontSize = 11.sp)
    }
}

@Composable
private fun V2Servers(groups: List<RuntimeSelectorGroup>, groupTag: String?, selected: String?, offlinePings: Map<String, Int>, onSelect: (String, String) -> Unit, profileId: String?, reliabilityScores: Map<String, Int>, updatedAt: Long?, busy: Boolean, onRefresh: () -> Unit) {
    var query by rememberSaveable { mutableStateOf("") }
    var filter by rememberSaveable { mutableStateOf("Все") }
    val allServers = groups.flatMap { it.items }
    val servers = allServers.filter { item ->
        val matchesText = query.isBlank() || item.tag.contains(query, true) || item.type.contains(query, true)
        val region = serverRegion(item.tag)
        val matchesFilter = filter == "Все" || region == filter
        matchesText && matchesFilter
    }
    Column(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Color(0xFF05111F), Aurora.Night))).verticalScroll(rememberScrollState()).padding(20.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text("Серверы", style = MaterialTheme.typography.displaySmall, color = Aurora.Text, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
            TextButton(onClick = onRefresh, enabled = !busy) { Text("Обновить пинг", color = Aurora.Mint) }
        }
        Text(updatedAt?.let { "Список · " + java.text.SimpleDateFormat("dd.MM HH:mm", java.util.Locale.getDefault()).format(java.util.Date(it)) } ?: "Загружаем список…", color = Aurora.Muted, fontSize = 12.sp, modifier = Modifier.padding(bottom = 12.dp))
        Surface(
            color = Aurora.Glass.copy(alpha = .92f),
            border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Mint.copy(alpha = .42f)),
            shape = RoundedCornerShape(22.dp),
            modifier = Modifier.fillMaxWidth().height(150.dp).padding(bottom = 12.dp),
        ) {
            Box {
                Globe3DBackdrop(Modifier.fillMaxSize(), pulse = true, reduceMotion = false, countryCode = null)
                Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.SpaceBetween) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Живая карта серверов", color = Aurora.Text, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                        Text("● LIVE", color = Aurora.Mint, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                    }
                    Text("${servers.size} точек · пинг обновляется каждые 20 секунд", color = Aurora.Muted, fontSize = 12.sp)
                }
            }
        }
        OutlinedTextField(
            value = query, onValueChange = { query = it }, singleLine = true,
            label = { Text("Найти страну или сервер") }, modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
        )
        Row(Modifier.fillMaxWidth().padding(bottom = 14.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf("Все", "Европа", "Азия", "Америка").forEach { option ->
                Surface(
                    onClick = { filter = option }, shape = RoundedCornerShape(18.dp),
                    color = if (filter == option) Aurora.Mint else Aurora.Glass,
                    border = androidx.compose.foundation.BorderStroke(1.dp, if (filter == option) Aurora.Mint else Aurora.Border),
                ) { Text(option, color = if (filter == option) Aurora.Night else Aurora.Muted, modifier = Modifier.padding(horizontal = 13.dp, vertical = 8.dp), fontSize = 12.sp) }
            }
        }
        fun reliability(server: com.quantumvpn.vpn.RuntimeOutboundItem): Int {
            val owner = groups.firstOrNull { group -> group.items.any { it.tag == server.tag } }
            val key = if (profileId != null && owner != null) {
                DeadServerQuarantineStore.serverKey(profileId, owner.tag, server.tag)
            } else server.tag
            return reliabilityScores[key] ?: reliabilityScores[server.tag] ?: 50
        }
        val bestServer = servers.mapNotNull { server ->
            (server.pingMillis ?: offlinePings[server.tag])?.let { ping ->
                Triple(server, ping, ServerHealthScore.combined(ping, reliability(server)))
            }
        }.sortedWith(
            compareByDescending<Triple<com.quantumvpn.vpn.RuntimeOutboundItem, Int, Int>> { it.third }
                .thenBy { it.second },
        ).firstOrNull()
        if (bestServer != null && groupTag != null) {
            Surface(
                onClick = {
                    groups.firstOrNull { group -> group.items.any { it.tag == bestServer.first.tag } }
                        ?.let { onSelect(it.tag, bestServer.first.tag) }
                },
                color = Aurora.Mint.copy(alpha = .13f),
                border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Mint.copy(alpha = .7f)),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
            ) {
                Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("⚡", fontSize = 24.sp)
                    Column(Modifier.weight(1f).padding(start = 10.dp)) {
                        Text("Умный автоматический выбор", color = Aurora.Text, fontWeight = FontWeight.SemiBold)
                        Text("${bestServer.first.tag} · качество ${bestServer.third}/100", color = Aurora.Muted, fontSize = 12.sp)
                    }
                    Text("${bestServer.second} мс", color = Aurora.Mint, fontWeight = FontWeight.Bold)
                }
            }
        }
        if (servers.isEmpty()) Text("Серверы не найдены", color = Aurora.Muted, modifier = Modifier.padding(top = 24.dp))
        servers.forEach { server ->
            Surface(
                onClick = { groups.firstOrNull { group -> group.items.any { it.tag == server.tag } }?.let { onSelect(it.tag, server.tag) } },
                color = if (server.tag == selected) Aurora.Violet.copy(alpha = .36f) else Aurora.Glass,
                border = androidx.compose.foundation.BorderStroke(1.dp, if (server.tag == selected) Aurora.Mint.copy(alpha = .72f) else Aurora.Border),
                shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth().padding(bottom = 10.dp),
            ) {
                Row(Modifier.padding(15.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(serverFlag(server.tag), fontSize = 25.sp)
                    Column(Modifier.weight(1f).padding(start = 12.dp)) {
                        Text(server.tag, color = Aurora.Text, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(server.type.uppercase(), color = Aurora.Muted, fontSize = 12.sp)
                    }
                    val ping = server.pingMillis ?: offlinePings[server.tag]
                    Surface(color = Aurora.Mint.copy(alpha = .12f), border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Mint.copy(alpha = .65f)), shape = RoundedCornerShape(14.dp)) {
                        Text(ping?.let { "$it мс · ${ServerHealthScore.combined(it, reliability(server))}" } ?: "…", color = Aurora.Mint, fontWeight = FontWeight.Bold, modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun V2Statistics(
    stats: VpnSessionStats,
    connected: Boolean,
    history: List<SessionTrafficRecord>,
    switchHistory: List<ServerSwitchEvent>,
    diagnostics: DiagnosticState,
    cumulativeBlocked: Long,
) {
    Column(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Color(0xFF05111F), Aurora.Night))).verticalScroll(rememberScrollState()).padding(20.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text("Статистика", style = MaterialTheme.typography.displaySmall, color = Aurora.Text, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
            Surface(color = Aurora.Glass, border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border), shape = RoundedCornerShape(999.dp)) {
                Text("Сегодня", color = Aurora.Muted, fontSize = 12.sp, modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp))
            }
        }
        Spacer(Modifier.height(14.dp))
        Surface(color = Aurora.Glass, border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border), shape = RoundedCornerShape(22.dp), modifier = Modifier.fillMaxWidth()) {
            Row(Modifier.padding(18.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("🌐", fontSize = 28.sp)
                Column(Modifier.padding(start = 12.dp)) {
                    Text(if (connected) "Подключено" else "Не подключено", color = if (connected) Aurora.Mint else Aurora.Text, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                    Text(
                        if (connected) "Соединение активно — статистика обновляется" else "Запустите подключение, чтобы увидеть полную статистику",
                        color = Aurora.Muted,
                        fontSize = 12.sp,
                    )
                }
            }
        }
        Spacer(Modifier.height(12.dp))
        val speed = stats.samples.lastOrNull()
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            V2Metric("Пинг", stats.pingMillis?.let { "$it мс" } ?: "—", Modifier.weight(1f))
            V2Metric("Загрузка", speed?.let { formatBytes(it.downloadBytesPerSecond) + "/с" } ?: "0 Б/с", Modifier.weight(1f))
            V2Metric("Отдача", speed?.let { formatBytes(it.uploadBytesPerSecond) + "/с" } ?: "0 Б/с", Modifier.weight(1f))
        }
        Spacer(Modifier.height(14.dp))
        TrafficChart(stats)
        var now by remember { mutableStateOf(System.currentTimeMillis()) }
        LaunchedEffect(connected) { while (connected) { now = System.currentTimeMillis(); kotlinx.coroutines.delay(1000) } }
        val seconds = stats.connectedAtEpochMillis?.let { ((now - it) / 1000).coerceAtLeast(0) } ?: 0
        Spacer(Modifier.height(4.dp))
        Text("Время подключения  %02d:%02d:%02d".format(seconds / 3600, seconds / 60 % 60, seconds % 60), color = Aurora.Muted, fontSize = 13.sp)
        Spacer(Modifier.height(6.dp))
        Text("Общий трафик  ${formatBytes(stats.downloadTotalBytes + stats.uploadTotalBytes)}", color = Aurora.Muted, fontSize = 13.sp)
        Spacer(Modifier.height(6.dp))
        Text("Сессий сегодня  ${history.size}", color = Aurora.Muted, fontSize = 13.sp)
        if (history.isNotEmpty()) {
            Spacer(Modifier.height(14.dp))
            Text("Последние сеансы", color = Aurora.Text, fontWeight = FontWeight.Bold)
            history.take(7).forEach { record ->
                val total = record.downloadBytes + record.uploadBytes
                Text("${record.profileName} · ${formatBytes(total)} · ${record.durationSec / 60} мин", color = Aurora.Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 6.dp))
            }
        }
        if (switchHistory.isNotEmpty()) {
            Spacer(Modifier.height(18.dp))
            Text("История смены серверов", color = Aurora.Text, fontWeight = FontWeight.Bold)
            switchHistory.take(6).forEach { event ->
                val date = java.text.SimpleDateFormat("dd.MM HH:mm", java.util.Locale.getDefault()).format(java.util.Date(event.epochMillis))
                Text("$date · ${event.outboundTag}", color = Aurora.Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 6.dp))
            }
        }
    }
}

@Composable
private fun V2Settings(
    diagnostics: DiagnosticState,
    policy: ClientPolicy,
    theme: ThemeMode,
    dynamicColor: Boolean,
    autoConnect: Boolean,
    notifications: Boolean,
    protectUnknownWifi: Boolean,
    travelMode: Boolean,
    adBlock: Boolean,
    killSwitch: Boolean,
    onTheme: (ThemeMode) -> Unit,
    onDynamicColor: (Boolean) -> Unit,
    onAutoConnect: (Boolean) -> Unit,
    onNotifications: (Boolean) -> Unit,
    onProtectUnknownWifi: (Boolean) -> Unit,
    onTravelMode: (Boolean) -> Unit,
    onAdBlock: (Boolean) -> Unit,
    onKillSwitch: (Boolean) -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var logStatus by remember { mutableStateOf("") }
    var privacyOpen by rememberSaveable { mutableStateOf(false) }
    var notificationsOpen by rememberSaveable { mutableStateOf(false) }
    var aboutOpen by rememberSaveable { mutableStateOf(false) }
    var donateOpen by rememberSaveable { mutableStateOf(false) }
    if (privacyOpen) {
        V2PrivacyPage(onBack = { privacyOpen = false })
        return
    }
    if (notificationsOpen) {
        V2NotificationCenterPage(
            policy = policy,
            onBack = { notificationsOpen = false },
            onOpenSystemSettings = {
                runCatching {
                    context.startActivity(
                        Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
                            putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
                        },
                    )
                }
            },
        )
        return
    }
    if (donateOpen) {
        V2DonationPage(onBack = { donateOpen = false })
        return
    }
    if (aboutOpen) {
        Column(
            Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Aurora.VioletNight, Aurora.Night))).verticalScroll(rememberScrollState()).padding(20.dp),
        ) {
            TextButton(onClick = { aboutOpen = false }) { Text("← Назад") }
            Text("О приложении", style = MaterialTheme.typography.displaySmall, color = Aurora.Text, fontWeight = FontWeight.Bold)
            Text("QuantumVPN ${BuildConfig.VERSION_NAME}", color = Aurora.Mint, modifier = Modifier.padding(top = 12.dp))
            Text("Liquid Glass Orbit · защита соединения", color = Aurora.Muted, modifier = Modifier.padding(top = 6.dp))
        }
        return
    }
    Column(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Color(0xFF05111F), Aurora.Night))).verticalScroll(rememberScrollState()).padding(20.dp)) {
        Text("Настройки", style = MaterialTheme.typography.displaySmall, color = Aurora.Text, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(18.dp))
        Text("Оформление", color = Aurora.Mint, fontSize = 12.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(bottom = 8.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf(ThemeMode.Light, ThemeMode.Dark, ThemeMode.System).forEach { mode ->
                Surface(
                    onClick = { onTheme(mode) },
                    color = if (theme == mode) Aurora.Mint else Aurora.Glass,
                    border = androidx.compose.foundation.BorderStroke(1.dp, if (theme == mode) Aurora.Mint else Aurora.Border),
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier.weight(1f),
                ) {
                    Text(
                        when (mode) {
                            ThemeMode.Light -> "Светлая"
                            ThemeMode.Dark -> "Тёмная"
                            ThemeMode.System -> "Системная"
                        },
                        color = if (theme == mode) Aurora.Night else Aurora.Muted,
                        textAlign = TextAlign.Center,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(vertical = 12.dp),
                    )
                }
            }
        }
        Spacer(Modifier.height(10.dp))
        V2Toggle("Цвета устройства", "Использовать акцент Android Dynamic Color", dynamicColor, onDynamicColor)
        Spacer(Modifier.height(16.dp))
        V2Toggle("Автоподключение", "Подключать VPN при запуске на мобильной сети", autoConnect, onAutoConnect)
        Spacer(Modifier.height(10.dp))
        V2Toggle("Уведомления", "Показывать статус соединения", notifications, onNotifications)
        Spacer(Modifier.height(10.dp))
        V2Toggle("Защита незнакомого Wi‑Fi", "Предложить VPN после страницы входа", protectUnknownWifi, onProtectUnknownWifi)
        Spacer(Modifier.height(10.dp))
        V2Toggle("Режим поездки", "Защита роуминга, автообход и быстрый failover", travelMode, onTravelMode)
        Spacer(Modifier.height(10.dp))
        Text("Безопасность", color = Aurora.Mint, fontSize = 12.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 8.dp, bottom = 2.dp))
        V2Toggle("Блокировка рекламы", "DNS-фильтры работают только во время VPN-сессии", adBlock, onAdBlock)
        Spacer(Modifier.height(10.dp))
        V2Toggle("Аварийное отключение", "Блокировать трафик при разрыве VPN", killSwitch, onKillSwitch)
        Spacer(Modifier.height(10.dp))
        V2NavRow(
            "Центр уведомлений",
            if (policy.maintenance) "Технические работы активны" else "Обновления и объявления сервиса",
            onClick = { notificationsOpen = true },
        )
        Spacer(Modifier.height(10.dp))
        V2Toggle("Диагностика сети", "Помогать улучшать стабильность (добровольно)", true) { }
        Spacer(Modifier.height(18.dp))
        V2NavRow("Пожертвование", "Поддержать проект через ЮMoney · история сборов", onClick = { donateOpen = true })
        Spacer(Modifier.height(10.dp))
        V2NavRow("Отправить логи", "Добровольный диагностический отчёт", onClick = {
            scope.launch {
                logStatus = "Отправка…"
                logStatus = if (VoluntaryDiagnosticReporter(context).send(diagnostics).isSuccess) {
                    "Отчёт отправлен в панель"
                } else {
                    "Не удалось отправить отчёт"
                }
            }
        })
        if (logStatus.isNotBlank()) Text(logStatus, color = Aurora.Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp))
        Spacer(Modifier.height(10.dp))
        V2NavRow("О приложении", "Версия и информация", onClick = { aboutOpen = true })
        Spacer(Modifier.height(10.dp))
        V2NavRow("Конфиденциальность", "Что хранится на устройстве и что отправляется", onClick = { privacyOpen = true })
    }
}

@Composable
private fun V2NotificationCenterPage(
    policy: ClientPolicy,
    onBack: () -> Unit,
    onOpenSystemSettings: () -> Unit,
) {
    Column(
        Modifier.fillMaxSize()
            .background(Brush.verticalGradient(listOf(Color(0xFF05111F), Aurora.Night)))
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
    ) {
        TextButton(onClick = onBack) { Text("← Назад", color = Aurora.Mint) }
        Text("Центр уведомлений", style = MaterialTheme.typography.displaySmall, color = Aurora.Text, fontWeight = FontWeight.Bold)
        Text("Обновления, состояние сервиса и важные объявления", color = Aurora.Muted, fontSize = 13.sp, modifier = Modifier.padding(top = 6.dp, bottom = 16.dp))
        Surface(
            color = if (policy.maintenance) Aurora.Danger.copy(alpha = .14f) else Aurora.Glass,
            border = androidx.compose.foundation.BorderStroke(1.dp, if (policy.maintenance) Aurora.Danger else Aurora.Border),
            shape = RoundedCornerShape(20.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(Modifier.padding(16.dp)) {
                Text(if (policy.maintenance) "Технические работы" else "Сервис работает", color = if (policy.maintenance) Aurora.Danger else Aurora.Mint, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                Text(
                    policy.maintenanceMessage.ifBlank { "Новых ограничений нет. Уведомления о важных изменениях будут показаны здесь." },
                    color = Aurora.Muted,
                    fontSize = 13.sp,
                    modifier = Modifier.padding(top = 6.dp),
                )
            }
        }
        Spacer(Modifier.height(12.dp))
        Surface(
            color = Aurora.Glass,
            border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border),
            shape = RoundedCornerShape(20.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(Modifier.padding(16.dp)) {
                Text("Последняя версия", color = Aurora.Text, fontWeight = FontWeight.SemiBold)
                Text(
                    if (policy.latestVersion.isBlank()) "Проверяем обновления при запуске" else "QuantumVPN ${policy.latestVersion} · versionCode ${policy.versionCode}",
                    color = Aurora.Mint,
                    modifier = Modifier.padding(top = 6.dp),
                )
                Text("Автопроверка выполняется при запуске и в фоне.", color = Aurora.Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp))
            }
        }
        if (policy.activeAnnounce().isNotBlank()) {
            Spacer(Modifier.height(12.dp))
            Surface(color = Aurora.Glass, border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Mint.copy(alpha = .45f)), shape = RoundedCornerShape(20.dp), modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Объявление оператора", color = Aurora.Text, fontWeight = FontWeight.SemiBold)
                    Text(policy.activeAnnounce(), color = Aurora.Muted, fontSize = 13.sp, modifier = Modifier.padding(top = 6.dp))
                }
            }
        }
        Spacer(Modifier.height(16.dp))
        V2NavRow("Настройки Android", "Разрешить или изменить уведомления QuantumVPN", onClick = onOpenSystemSettings)
    }
}

@Composable
private fun V2DonationPage(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val repo = remember(context) { DonationRepository(context) }
    var local by remember { mutableStateOf(repo.localHistory()) }
    var summary by remember { mutableStateOf(DonationSummary()) }
    var status by remember { mutableStateOf("") }
    var sending by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        summary = repo.fetchSummary()
    }
    fun report(amount: Int) {
        if (sending || amount < 1) return
        sending = true
        status = "Сохраняем…"
        scope.launch {
            val result = repo.reportDonation(amount)
            local = repo.localHistory()
            result.onSuccess {
                summary = it
                status = "Спасибо! ${DonationRepository.formatRub(amount)} отмечены"
            }.onFailure {
                status = "Сохранено на устройстве. Сервер временно недоступен."
            }
            sending = false
        }
    }
    Column(
        Modifier
            .fillMaxSize()
            .background(Brush.verticalGradient(listOf(Aurora.VioletNight, Aurora.Night)))
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
    ) {
        TextButton(onClick = onBack) { Text("← Назад") }
        Text("Пожертвование", style = MaterialTheme.typography.displaySmall, color = Aurora.Text, fontWeight = FontWeight.Bold)
        Text("Поддержите QuantumVPN через ЮMoney", color = Aurora.Muted, modifier = Modifier.padding(top = 4.dp, bottom = 14.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            V2Metric("Всего собрано", if (summary.totalRub > 0) DonationRepository.formatRub(summary.totalRub) else "—", Modifier.weight(1f))
            V2Metric("Ваши", DonationRepository.formatRub(repo.localTotalRub()), Modifier.weight(1f))
        }
        Spacer(Modifier.height(14.dp))
        Surface(
            color = Aurora.Glass,
            border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border),
            shape = RoundedCornerShape(18.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(Modifier.padding(16.dp)) {
                Text("Оплата ЮMoney", color = Aurora.Text, fontWeight = FontWeight.SemiBold)
                Text("Откроется внешний браузер. Сумма на странице начинается с 0 ₽ и не сохраняется приложением.", color = Aurora.Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp, bottom = 12.dp))
                Button(
                    onClick = {
                        runCatching {
                            context.startActivity(
                                Intent(Intent.ACTION_VIEW, Uri.parse(DonationRepository.YOOMONEY_PAGE_URL)),
                            )
                        }.onFailure { status = "Не удалось открыть браузер" }
                    },
                    enabled = !sending,
                    colors = ButtonDefaults.buttonColors(containerColor = Aurora.Mint, contentColor = Aurora.Night),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Открыть ЮMoney во внешнем браузере", fontWeight = FontWeight.Bold)
                }
            }
        }
        Spacer(Modifier.height(14.dp))
        Text("Я отправил", color = Aurora.Mint, fontSize = 12.sp, fontWeight = FontWeight.Bold)
        Text("Отметьте сумму после оплаты — она попадёт в историю", color = Aurora.Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp, bottom = 10.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf(50, 100, 200, 500).forEach { amount ->
                Surface(
                    onClick = { report(amount) },
                    enabled = !sending,
                    color = Aurora.Glass,
                    border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border),
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier.weight(1f),
                ) {
                    Text(
                        "$amount ₽",
                        color = Aurora.Text,
                        textAlign = TextAlign.Center,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 13.sp,
                        modifier = Modifier.padding(vertical = 12.dp),
                    )
                }
            }
        }
        if (status.isNotBlank()) {
            Text(status, color = Aurora.Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp))
        }
        Spacer(Modifier.height(18.dp))
        Text("Общая история", color = Aurora.Text, fontWeight = FontWeight.Bold)
        if (summary.recent.isEmpty()) {
            Text("Пока нет отмеченных пожертвований на сервере", color = Aurora.Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp))
        } else {
            summary.recent.take(12).forEach { entry ->
                DonationHistoryRow(entry)
            }
        }
        Spacer(Modifier.height(16.dp))
        Text("Ваша история на устройстве", color = Aurora.Text, fontWeight = FontWeight.Bold)
        if (local.isEmpty()) {
            Text("Вы ещё ничего не отмечали", color = Aurora.Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp))
        } else {
            local.take(20).forEach { entry ->
                DonationHistoryRow(entry)
            }
        }
        Spacer(Modifier.height(20.dp))
    }
}

@Composable
private fun DonationHistoryRow(entry: DonationEntry) {
    Surface(
        color = Aurora.Glass,
        border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border.copy(alpha = .7f)),
        shape = RoundedCornerShape(14.dp),
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
    ) {
        Row(Modifier.padding(horizontal = 14.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(DonationRepository.formatRub(entry.amountRub), color = Aurora.Text, fontWeight = FontWeight.SemiBold)
                Text(DonationRepository.formatWhen(entry.ts), color = Aurora.Muted, fontSize = 12.sp)
            }
            if (entry.label.isNotBlank()) {
                Text(entry.label, color = Aurora.Muted, fontSize = 11.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

@Composable
private fun V2PrivacyPage(onBack: () -> Unit) {
    Column(
        Modifier
            .fillMaxSize()
            .background(Brush.verticalGradient(listOf(Aurora.VioletNight, Aurora.Night)))
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
    ) {
        TextButton(onClick = onBack) { Text("← Назад") }
        Text("Конфиденциальность", style = MaterialTheme.typography.displaySmall, color = Aurora.Text, fontWeight = FontWeight.Bold)
        Text("Данные остаются под вашим контролем", color = Aurora.Muted, modifier = Modifier.padding(top = 4.dp, bottom = 18.dp))
        listOf(
            "История сайтов и DNS-запросов не сохраняется",
            "Подписки и ключи хранятся локально в Android Keystore",
            "Диагностика отправляется только после нажатия кнопки",
            "Отчёт очищается от ссылок, ключей и других секретов",
            "Обновления APK проверяются по SHA-256 и подписи",
        ).forEach { item ->
            V2StatusRow(item, "Включено по умолчанию", true)
            Spacer(Modifier.height(10.dp))
        }
    }
}

@Composable private fun V2Metric(title: String, value: String, modifier: Modifier) = Surface(color = Aurora.Glass, border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border), shape = RoundedCornerShape(18.dp), modifier = modifier) { Column(Modifier.padding(16.dp)) { Text(title, color = Aurora.Muted); Text(value, color = Aurora.Text, fontWeight = FontWeight.Bold, fontSize = 20.sp) } }
@Composable private fun V2Toggle(title: String, subtitle: String, checked: Boolean, onChange: (Boolean) -> Unit) = Surface(color = Aurora.Glass, border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border), shape = RoundedCornerShape(18.dp), modifier = Modifier.fillMaxWidth()) { Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) { Column(Modifier.weight(1f)) { Text(title, color = Aurora.Text, fontWeight = FontWeight.SemiBold); Text(subtitle, color = Aurora.Muted, fontSize = 12.sp) }; Switch(checked = checked, onCheckedChange = onChange, colors = SwitchDefaults.colors(checkedThumbColor = Aurora.Mint, checkedTrackColor = Aurora.Violet.copy(alpha = .72f))) } }
@Composable private fun V2StatusRow(title: String, subtitle: String, good: Boolean) = Surface(color = Aurora.Glass, border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border), shape = RoundedCornerShape(18.dp), modifier = Modifier.fillMaxWidth()) { Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) { Icon(Icons.Default.CheckCircle, null, tint = if (good) Aurora.Mint else Aurora.Muted); Column(Modifier.padding(start = 12.dp)) { Text(title, color = Aurora.Text, fontWeight = FontWeight.SemiBold); Text(subtitle, color = Aurora.Muted, fontSize = 12.sp) } } }
@Composable private fun V2NavRow(title: String, subtitle: String, onClick: () -> Unit) = Surface(onClick = onClick, color = Aurora.Glass, border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border), shape = RoundedCornerShape(18.dp), modifier = Modifier.fillMaxWidth()) { Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) { Column(Modifier.weight(1f)) { Text(title, color = Aurora.Text, fontWeight = FontWeight.SemiBold); Text(subtitle, color = Aurora.Muted, fontSize = 12.sp) }; Text("›", color = Aurora.Mint, fontSize = 24.sp) } }
@Composable private fun V2BottomBar(tab: V2Tab, onTab: (V2Tab) -> Unit) = Surface(color = Aurora.Glass, border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border.copy(alpha = .7f)), shape = RoundedCornerShape(topStart = 20.dp, topEnd = 20.dp), shadowElevation = 14.dp, modifier = Modifier.fillMaxWidth().navigationBarsPadding()) { Row(Modifier.fillMaxWidth().padding(vertical = 5.dp), horizontalArrangement = Arrangement.SpaceEvenly) { V2Tab.entries.forEach { item -> Column(Modifier.clickable { onTab(item) }.padding(horizontal = 8.dp, vertical = 3.dp), horizontalAlignment = Alignment.CenterHorizontally) { Icon(item.icon, null, tint = if (item == tab) Aurora.Mint else Aurora.Muted, modifier = Modifier.size(22.dp)); Text(item.title, color = if (item == tab) Aurora.Mint else Aurora.Muted, fontSize = 10.sp) } } } }

@Composable
private fun V2BrandHeader(subtitle: String) {
    Row(Modifier.fillMaxWidth().padding(bottom = 22.dp), verticalAlignment = Alignment.CenterVertically) {
        Surface(shape = CircleShape, color = Aurora.Violet.copy(alpha = .18f), border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Mint.copy(alpha = .55f)), modifier = Modifier.size(42.dp)) {
            Box(contentAlignment = Alignment.Center) { Text("Q", color = Aurora.Mint, fontSize = 24.sp, fontWeight = FontWeight.Bold) }
        }
        Column(Modifier.padding(start = 10.dp)) {
            Row { Text("Quantum", color = Aurora.Text, fontSize = 20.sp, fontWeight = FontWeight.Bold); Text("VPN", color = Aurora.Mint, fontSize = 20.sp, fontWeight = FontWeight.Bold) }
            Text(subtitle, color = Aurora.Muted, fontSize = 11.sp)
        }
    }
}
@Composable
private fun TrafficChart(stats: VpnSessionStats) {
    val samples = stats.samples.takeLast(60)
    val mint = Aurora.Mint
    val violet = Aurora.Violet
    val border = Aurora.Border
    Surface(color = Aurora.Glass, shape = RoundedCornerShape(18.dp), modifier = Modifier.fillMaxWidth().padding(bottom = 14.dp)) {
        Column(Modifier.padding(16.dp)) {
            Text("Трафик", color = Aurora.Text, fontWeight = FontWeight.Bold)
            Text("Загрузка · Отдача", color = Aurora.Muted, fontSize = 12.sp)
            if (samples.size < 2) Text("График появится после получения данных", color = Aurora.Muted, modifier = Modifier.padding(vertical = 24.dp))
            else Canvas(Modifier.fillMaxWidth().height(130.dp).padding(top = 16.dp)) {
                val peak = samples.maxOf { maxOf(it.downloadBytesPerSecond, it.uploadBytesPerSecond) }.coerceAtLeast(1).toFloat()
                for (row in 0..3) drawLine(border.copy(alpha = .4f), Offset(0f, size.height * row / 3), Offset(size.width, size.height * row / 3))
                samples.zipWithNext().forEachIndexed { i, (a, b) ->
                    val x1 = size.width * i / (samples.size - 1)
                    val x2 = size.width * (i + 1) / (samples.size - 1)
                    drawLine(mint, Offset(x1, size.height * (1 - a.downloadBytesPerSecond / peak)), Offset(x2, size.height * (1 - b.downloadBytesPerSecond / peak)), 3.dp.toPx())
                    drawLine(violet, Offset(x1, size.height * (1 - a.uploadBytesPerSecond / peak)), Offset(x2, size.height * (1 - b.uploadBytesPerSecond / peak)), 2.dp.toPx())
                }
            }
        }
    }
}
