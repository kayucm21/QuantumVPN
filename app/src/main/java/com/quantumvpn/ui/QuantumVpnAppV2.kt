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
import com.quantumvpn.diagnostics.VoluntaryDiagnosticReporter
import com.quantumvpn.profiles.ProfilesUiState
import com.quantumvpn.profiles.ProfilesViewModel
import com.quantumvpn.vpn.RuntimeSelectorGroup
import com.quantumvpn.vpn.VpnConnectionState
import com.quantumvpn.vpn.VpnSessionStats
import com.quantumvpn.vpn.forServerUi
import com.quantumvpn.vpn.primaryGroup
import com.quantumvpn.vpn.UnderlyingServerPing

private enum class V2Tab(val title: String, val icon: ImageVector) {
    Home("Главная", Icons.Default.Home),
    Servers("Серверы", Icons.AutoMirrored.Filled.List),
    Statistics("Статистика", Icons.Default.Menu),
    Settings("Настройки", Icons.Default.Settings),
}

/** Aurora C — violet/mint glass visual language used by every production tab. */
private val LocalAuroraDark = staticCompositionLocalOf { true }
private object Aurora {
    val Night: Color @Composable get() = if (LocalAuroraDark.current) Color(0xFF020F19) else Color(0xFFF2F7F6)
    val VioletNight: Color @Composable get() = if (LocalAuroraDark.current) Color(0xFF071E2A) else Color(0xFFE3F1EF)
    val Glass: Color @Composable get() = if (LocalAuroraDark.current) Color(0xE30A2432) else Color(0xEFFFFFFF)
    val Mint: Color @Composable get() = if (LocalAuroraDark.current) Color(0xFF2EF2A3) else Color(0xFF00745B)
    val Violet: Color @Composable get() = if (LocalAuroraDark.current) Color(0xFF9A7AF5) else Color(0xFF6550A8)
    val Text: Color @Composable get() = if (LocalAuroraDark.current) Color(0xFFF5F2FF) else Color(0xFF211D35)
    val Muted: Color @Composable get() = if (LocalAuroraDark.current) Color(0xFFB9B6D1) else Color(0xFF605976)
    val Border: Color @Composable get() = if (LocalAuroraDark.current) Color(0xFF24506A) else Color(0xFFB8D0D0)
}

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
    val block = policy.blockReason(BuildConfig.VERSION_CODE.toLong())
    LaunchedEffect(block, connected) {
        if (block != null && connected) onVpnStop()
    }
    val dark = when (state.settings.themeMode) {
        ThemeMode.System -> isSystemInDarkTheme()
        ThemeMode.Dark -> true
        ThemeMode.Light -> false
    }
    CompositionLocalProvider(LocalAuroraDark provides dark) {
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
                        connected = connected,
                        busy = busy,
                        hasProfile = activeProfile != null,
                        server = selected?.tag ?: "Автоматический сервер",
                        ping = selected?.pingMillis ?: selected?.tag?.let(offlinePings::get),
                        adBlock = state.settings.adBlockEnabled,
                        stats = sessionStats,
                        onConnect = {
                            val id = activeProfile?.id
                            if (id == null) viewModel.installManagedSubscription()
                            else if (connected) onVpnStop()
                            else if (block == null && !busy) onVpnStart(id)
                        },
                        onServers = { tab = V2Tab.Servers },
                    )
                    V2Tab.Servers -> V2Servers(groups, mainGroup?.tag, mainGroup?.selected, offlinePings, onSelectServer, activeProfile?.updatedAtEpochMillis, state.busy) { viewModel.refreshAllSubscriptionsQuietly() }
                    V2Tab.Statistics -> V2Statistics(sessionStats, connected)
                    V2Tab.Settings -> V2Settings(
                        adBlock = state.settings.adBlockEnabled,
                        killSwitch = state.settings.blockNonVpnTraffic,
                        diagnostics = diagnostics,
                        theme = state.settings.themeMode,
                        onTheme = viewModel::setTheme,
                        updateState = updateState,
                        onCheckUpdate = onCheckUpdate,
                        onAdBlock = viewModel::setAdBlockEnabled,
                        onKillSwitch = viewModel::setBlockNonVpnTraffic,
                    )
                }
            }
            V2BottomBar(tab = tab, onTab = { tab = it })
        }
    }
    when (val update = updateState) {
        is UpdateState.Available -> UpdateAvailableDialog(update.candidate, onDownloadUpdate, onCancelUpdate)
        is UpdateState.Downloading -> UpdateDownloadingDialog(update.candidate, update.downloadedBytes, update.totalBytes, onCancelUpdate)
        is UpdateState.Ready -> UpdateReadyDialog(update.candidate, onInstallUpdate, onCancelUpdate)
        is UpdateState.Failure -> AlertDialog(onDismissRequest = onCancelUpdate, title = { Text("Обновление") }, text = { Text(update.message) }, confirmButton = { TextButton(onClick = onCheckUpdate) { Text("Повторить") } }, dismissButton = { TextButton(onClick = onCancelUpdate) { Text("Закрыть") } })
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

@Composable
private fun V2Home(
    connected: Boolean, busy: Boolean, hasProfile: Boolean, server: String, ping: Int?, adBlock: Boolean, stats: VpnSessionStats,
    onConnect: () -> Unit, onServers: () -> Unit,
) {
    Box(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Aurora.VioletNight, Aurora.Glass, Aurora.Night)))) {
        if (LocalAuroraDark.current) Globe3DBackdrop(Modifier.fillMaxSize(), pulse = connected || busy, reduceMotion = false, countryCode = null)
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 22.dp, vertical = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Surface(shape = CircleShape, color = Aurora.Violet.copy(alpha = 0.17f), border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Mint.copy(alpha = .55f)), modifier = Modifier.size(54.dp)) {
                    Box(contentAlignment = Alignment.Center) { Text("Q", color = Aurora.Mint, fontWeight = FontWeight.Bold, fontSize = 31.sp) }
                }
                Text("Quantum", color = Aurora.Text, fontSize = 29.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(start = 10.dp))
                Text("VPN", color = Aurora.Mint, fontSize = 29.sp, fontWeight = FontWeight.Bold)
            }
            Spacer(Modifier.height(20.dp))
            Surface(onClick = onServers, color = Aurora.Glass, border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border), shape = RoundedCornerShape(18.dp), modifier = Modifier.fillMaxWidth()) {
                Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("⚡", fontSize = 24.sp)
                    Column(Modifier.weight(1f).padding(start = 11.dp)) {
                        Text("Лучший сервер", color = Aurora.Text, fontWeight = FontWeight.SemiBold)
                        Text(server, color = Aurora.Muted, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    Surface(color = Aurora.Mint.copy(alpha = .12f), shape = RoundedCornerShape(13.dp)) {
                        Text(ping?.let { "$it мс" } ?: "авто", color = Aurora.Mint, fontWeight = FontWeight.Bold, modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp))
                    }
                }
            }
            Spacer(Modifier.height(18.dp))
            Text(
                if (connected) "Защита включена" else "Защита выключена",
                color = if (connected) Aurora.Mint else Color(0xFFFF9EAF),
                fontWeight = FontWeight.Bold,
                fontSize = 24.sp,
            )
            Spacer(Modifier.height(14.dp))
            Surface(
                shape = CircleShape,
                color = Aurora.Glass,
                border = androidx.compose.foundation.BorderStroke(2.dp, if (connected) Aurora.Mint else Aurora.Violet),
                modifier = Modifier.size(172.dp).clickable(enabled = !busy) { onConnect() },
            ) {
                Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
                    Icon(if (connected) Icons.Default.CheckCircle else Icons.Default.Lock, null, tint = Aurora.Mint, modifier = Modifier.size(54.dp))
                    Spacer(Modifier.height(9.dp))
                    Text(if (connected) "Отключить" else if (busy) "Подключение…" else "Подключить", color = Aurora.Text, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                    Text(if (connected) "Соединение защищено" else if (hasProfile) "Готово к подключению" else "Загружаем серверы", color = Aurora.Muted, fontSize = 13.sp)
                }
            }
            Spacer(Modifier.height(16.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                V2Metric("Трафик", formatBytes(stats.downloadTotalBytes + stats.uploadTotalBytes), Modifier.weight(1f))
                V2Metric("Защита", if (adBlock) "DNS активен" else "DNS выключен", Modifier.weight(1f))
            }
            Spacer(Modifier.height(12.dp))
            V2StatusRow("Блокировка рекламы", if (adBlock) "Активируется после подключения" else "Выключена", adBlock)
        }
    }
}

@Composable
private fun V2Servers(groups: List<RuntimeSelectorGroup>, groupTag: String?, selected: String?, offlinePings: Map<String, Int>, onSelect: (String, String) -> Unit, updatedAt: Long?, busy: Boolean, onRefresh: () -> Unit) {
    var query by rememberSaveable { mutableStateOf("") }
    var filter by rememberSaveable { mutableStateOf("Все") }
    val allServers = groups.flatMap { it.items }
    val servers = allServers.filter { item ->
        val matchesText = query.isBlank() || item.tag.contains(query, true) || item.type.contains(query, true)
        val matchesFilter = filter == "Все" || item.type.contains(filter, true) || item.tag.contains(filter, true)
        matchesText && matchesFilter
    }
    Column(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Aurora.VioletNight, Aurora.Night))).verticalScroll(rememberScrollState()).padding(20.dp)) {
        V2BrandHeader("Свобода без границ")
        Text("Серверы", style = MaterialTheme.typography.displaySmall, color = Aurora.Text, fontWeight = FontWeight.Bold)
        Text("Быстрый пинг и автоматическое обновление списка", color = Aurora.Muted, modifier = Modifier.padding(top = 4.dp, bottom = 18.dp))
        Text(updatedAt?.let { "Сохранённый список · " + java.text.SimpleDateFormat("dd.MM HH:mm", java.util.Locale.getDefault()).format(java.util.Date(it)) } ?: "Список ещё не загружен", color = Aurora.Muted, fontSize = 12.sp)
        TextButton(onClick = onRefresh, enabled = !busy) { Text("Обновить серверы") }
        OutlinedTextField(
            value = query, onValueChange = { query = it }, singleLine = true,
            label = { Text("Найти страну или сервер") }, modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
        )
        Row(Modifier.fillMaxWidth().padding(bottom = 14.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf("Все", "VLESS", "Hysteria").forEach { option ->
                Surface(
                    onClick = { filter = option }, shape = RoundedCornerShape(18.dp),
                    color = if (filter == option) Aurora.Mint else Aurora.Glass,
                ) { Text(option, color = if (filter == option) Aurora.Night else Aurora.Muted, modifier = Modifier.padding(horizontal = 13.dp, vertical = 8.dp), fontSize = 12.sp) }
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
                    Surface(color = Aurora.Mint.copy(alpha = .12f), border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Mint.copy(alpha = .65f)), shape = RoundedCornerShape(14.dp)) {
                        Text((server.pingMillis ?: offlinePings[server.tag])?.let { "$it мс" } ?: "…", color = Aurora.Mint, fontWeight = FontWeight.Bold, modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun V2Statistics(stats: VpnSessionStats, connected: Boolean) {
    Column(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Aurora.VioletNight, Aurora.Night))).verticalScroll(rememberScrollState()).padding(20.dp)) {
        V2BrandHeader(if (connected) "Онлайн · соединение защищено" else "Свобода без границ")
        Text("Статистика", style = MaterialTheme.typography.displaySmall, color = Aurora.Text, fontWeight = FontWeight.Bold)
        Text("Сеанс, трафик и качество соединения", color = Aurora.Muted, modifier = Modifier.padding(top = 4.dp, bottom = 18.dp))
        Surface(color = Aurora.Glass, border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border), shape = RoundedCornerShape(22.dp), modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(22.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Text(if (connected) "Текущий сеанс · защищён" else "Соединение пока выключено", color = Aurora.Muted)
                Text(formatBytes(stats.downloadTotalBytes + stats.uploadTotalBytes), color = Aurora.Text, fontSize = 42.sp, fontWeight = FontWeight.Bold)
                Text("↓ ${formatBytes(stats.downloadTotalBytes)}    ↑ ${formatBytes(stats.uploadTotalBytes)}", color = Aurora.Mint)
            }
        }
        Spacer(Modifier.height(14.dp))
        TrafficChart(stats)
        val speed = stats.samples.lastOrNull()
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            V2Metric("Загрузка", speed?.let { formatBytes(it.downloadBytesPerSecond) + "/с" } ?: "—", Modifier.weight(1f))
            V2Metric("Отдача", speed?.let { formatBytes(it.uploadBytesPerSecond) + "/с" } ?: "—", Modifier.weight(1f))
        }
        var now by remember { mutableStateOf(System.currentTimeMillis()) }
        LaunchedEffect(connected) { while (connected) { now = System.currentTimeMillis(); kotlinx.coroutines.delay(1000) } }
        val seconds = stats.connectedAtEpochMillis?.let { ((now - it) / 1000).coerceAtLeast(0) } ?: 0
        Text("Время сеанса: %02d:%02d:%02d".format(seconds / 3600, seconds / 60 % 60, seconds % 60), color = Aurora.Muted, modifier = Modifier.padding(vertical = 16.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            V2Metric("Ping", stats.pingMillis?.let { "$it мс" } ?: "—", Modifier.weight(1f))
            V2Metric("DNS-фильтр", stats.adBlockedSessionTotal.toString(), Modifier.weight(1f))
        }
    }
}

@Composable
private fun V2Settings(adBlock: Boolean, killSwitch: Boolean, diagnostics: DiagnosticState, theme: ThemeMode, onTheme: (ThemeMode) -> Unit, onAdBlock: (Boolean) -> Unit, onKillSwitch: (Boolean) -> Unit, updateState: UpdateState, onCheckUpdate: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var logStatus by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Aurora.VioletNight, Aurora.Night))).verticalScroll(rememberScrollState()).padding(20.dp)) {
        V2BrandHeader("Свобода без границ")
        Text("Настройки", style = MaterialTheme.typography.displaySmall, color = Aurora.Text, fontWeight = FontWeight.Bold)
        Text("Приватность, DNS и оформление", color = Aurora.Muted, modifier = Modifier.padding(top = 4.dp, bottom = 18.dp))
        Text("БЕЗОПАСНОСТЬ", color = Aurora.Mint, fontSize = 12.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(bottom = 8.dp))
        V2Toggle("DNS и блокировка рекламы", "dns.adguard-dns.com · включается только вместе с VPN", adBlock, onAdBlock)
        Spacer(Modifier.height(10.dp))
        V2Toggle("Kill switch", "Блокировать интернет при разрыве VPN", killSwitch, onKillSwitch)
        Spacer(Modifier.height(18.dp))
        Text("ПРИЛОЖЕНИЕ", color = Aurora.Mint, fontSize = 12.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(bottom = 8.dp))
        V2StatusRow("Диагностика", "Добровольный отчёт", true)
        Spacer(Modifier.height(10.dp))
        V2StatusRow("Оформление", "Северное сияние · фиолетово-мятное стекло", true)
        Spacer(Modifier.height(10.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ThemeMode.entries.forEach { mode ->
                Surface(onClick = { onTheme(mode) }, color = if (theme == mode) Aurora.Mint else Aurora.Glass, shape = RoundedCornerShape(14.dp), modifier = Modifier.weight(1f)) {
                    Text(when (mode) { ThemeMode.System -> "Система"; ThemeMode.Dark -> "Тёмная"; ThemeMode.Light -> "Светлая" }, color = if (theme == mode) Aurora.Night else Aurora.Muted, textAlign = TextAlign.Center, fontSize = 11.sp, modifier = Modifier.padding(vertical = 10.dp))
                }
            }
        }
        Spacer(Modifier.height(16.dp))
        Text("QuantumVPN ${BuildConfig.VERSION_NAME}", color = Aurora.Muted)
        TextButton(onClick = onCheckUpdate, enabled = updateState !is UpdateState.Checking && updateState !is UpdateState.Downloading) { Text(if (updateState is UpdateState.Checking) "Проверяем…" else "Проверить обновление") }
        if (updateState is UpdateState.UpToDate) Text("Установлена актуальная версия", color = Aurora.Mint)
        Button(onClick = { scope.launch { logStatus = "Отправка…"; logStatus = if (VoluntaryDiagnosticReporter(context).send(diagnostics).isSuccess) "Отчёт отправлен в панель" else "Не удалось отправить отчёт" } }, colors = ButtonDefaults.buttonColors(containerColor = Aurora.Mint, contentColor = Aurora.Night), modifier = Modifier.fillMaxWidth()) { Text("Отправить логи добровольно") }
        if (logStatus.isNotBlank()) Text(logStatus, color = Aurora.Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp))
    }
}

@Composable private fun V2Metric(title: String, value: String, modifier: Modifier) = Surface(color = Aurora.Glass, border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border), shape = RoundedCornerShape(18.dp), modifier = modifier) { Column(Modifier.padding(16.dp)) { Text(title, color = Aurora.Muted); Text(value, color = Aurora.Text, fontWeight = FontWeight.Bold, fontSize = 20.sp) } }
@Composable private fun V2Toggle(title: String, subtitle: String, checked: Boolean, onChange: (Boolean) -> Unit) = Surface(color = Aurora.Glass, border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border), shape = RoundedCornerShape(18.dp), modifier = Modifier.fillMaxWidth()) { Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) { Column(Modifier.weight(1f)) { Text(title, color = Aurora.Text, fontWeight = FontWeight.SemiBold); Text(subtitle, color = Aurora.Muted, fontSize = 12.sp) }; Switch(checked = checked, onCheckedChange = onChange, colors = SwitchDefaults.colors(checkedThumbColor = Aurora.Mint, checkedTrackColor = Aurora.Violet.copy(alpha = .72f))) } }
@Composable private fun V2StatusRow(title: String, subtitle: String, good: Boolean) = Surface(color = Aurora.Glass, border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border), shape = RoundedCornerShape(18.dp), modifier = Modifier.fillMaxWidth()) { Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) { Icon(Icons.Default.CheckCircle, null, tint = if (good) Aurora.Mint else Aurora.Muted); Column(Modifier.padding(start = 12.dp)) { Text(title, color = Aurora.Text, fontWeight = FontWeight.SemiBold); Text(subtitle, color = Aurora.Muted, fontSize = 12.sp) } } }
@Composable private fun V2BottomBar(tab: V2Tab, onTab: (V2Tab) -> Unit) = Surface(color = Aurora.Glass, border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border.copy(alpha = .7f)), shape = RoundedCornerShape(topStart = 20.dp, topEnd = 20.dp), modifier = Modifier.fillMaxWidth().navigationBarsPadding()) { Row(Modifier.fillMaxWidth().padding(vertical = 5.dp), horizontalArrangement = Arrangement.SpaceEvenly) { V2Tab.entries.forEach { item -> Column(Modifier.clickable { onTab(item) }.padding(horizontal = 8.dp, vertical = 3.dp), horizontalAlignment = Alignment.CenterHorizontally) { Icon(item.icon, null, tint = if (item == tab) Aurora.Mint else Aurora.Muted, modifier = Modifier.size(22.dp)); Text(item.title, color = if (item == tab) Aurora.Mint else Aurora.Muted, fontSize = 10.sp) } } } }

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
            Text("Скорость · ↓ загрузка / ↑ отдача", color = Aurora.Muted, fontSize = 12.sp)
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
