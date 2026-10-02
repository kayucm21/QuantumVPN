package com.quantumvpn.ui

import android.graphics.BitmapFactory
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
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
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.statusBarsPadding
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
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.changedToUpIgnoreConsumed
import androidx.compose.ui.input.pointer.pointerInput
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.quantumvpn.diagnostics.DiagnosticState
import com.quantumvpn.diagnostics.SessionTrafficRecord
import com.quantumvpn.diagnostics.VoluntaryDiagnosticReporter
import com.quantumvpn.donations.DonationEntry
import com.quantumvpn.donations.DonationRepository
import com.quantumvpn.donations.DonationSummary
import com.quantumvpn.cards.CardTableRepository
import com.quantumvpn.cards.CardTableSnapshot
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
    Cards("Карты", Icons.Default.CheckCircle),
}

/** Liquid Glass Orbit — cyan/blue glassmorphism matching the design mockup. */
private val LocalAuroraDark = staticCompositionLocalOf { true }
private val LocalAuroraAccent = staticCompositionLocalOf { Color(0xFF3DE7FF) }
private val LocalAuroraBackgroundStyle = staticCompositionLocalOf { AppBackgroundStyle.Aurora }
private val LocalAuroraCustomBackground = staticCompositionLocalOf<String?> { null }
private val LocalAuroraTouchBubbles = staticCompositionLocalOf { true }
private data class AuroraTapBubble(val id: Long, val origin: Offset)
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

/**
 * Aurora Glass is intentionally scoped to the non-home tabs.  It gives the
 * dense lists and settings pages the same depth as the new startup/home art
 * without changing any VPN, update, or server-selection behaviour.
 */
@Composable
private fun V2AuroraBackdrop(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    val mint = Aurora.Mint
    val dark = LocalAuroraDark.current
    val backgroundStyle = LocalAuroraBackgroundStyle.current
    val backgroundUri = LocalAuroraCustomBackground.current
    val touchBubbles = LocalAuroraTouchBubbles.current
    val context = LocalContext.current
    val violetBloom = if (dark) Color(0xFF8B5CF6) else Color(0xFF6D4AFF)
    val tealBloom = if (dark) Color(0xFF2EE5C8) else Color(0xFF00A58B)
    val customBitmap by produceState<android.graphics.Bitmap?>(
        initialValue = null,
        key1 = backgroundStyle,
        key2 = backgroundUri,
    ) {
        value = if (backgroundStyle == AppBackgroundStyle.Custom && !backgroundUri.isNullOrBlank()) {
            withContext(Dispatchers.IO) {
                runCatching {
                    decodeCustomBackground(context, Uri.parse(backgroundUri))
                }.getOrNull()
            }
        } else {
            null
        }
    }
    var tapBubbles by remember { mutableStateOf(emptyList<AuroraTapBubble>()) }
    tapBubbles.forEach { bubble ->
        LaunchedEffect(bubble.id) {
            kotlinx.coroutines.delay(520)
            tapBubbles = tapBubbles.filterNot { it.id == bubble.id }
        }
    }
    Box(
        modifier = modifier
            .pointerInput(touchBubbles) {
                if (touchBubbles) {
                    awaitPointerEventScope {
                        while (true) {
                            val up = awaitPointerEvent(PointerEventPass.Final).changes
                                .firstOrNull { it.changedToUpIgnoreConsumed() }
                            if (up != null) {
                                tapBubbles = (tapBubbles + AuroraTapBubble(System.nanoTime(), up.position)).takeLast(5)
                            }
                        }
                    }
                }
            }
            .background(
            Brush.verticalGradient(
                listOf(
                    when (backgroundStyle) {
                        AppBackgroundStyle.NightCity -> if (dark) Color(0xFF110B24) else Color(0xFFF1F0FA)
                        AppBackgroundStyle.DeepSpace -> if (dark) Color(0xFF020815) else Color(0xFFF1F7FF)
                        else -> if (dark) Color(0xFF100A2A) else Color(0xFFF4F7FF)
                    },
                    Aurora.VioletNight,
                    Aurora.Night,
                ),
            ),
        ),
    ) {
        customBitmap?.let { bitmap ->
            Image(
                bitmap = bitmap.asImageBitmap(),
                contentDescription = null,
                contentScale = ContentScale.Crop,
                alpha = if (dark) .34f else .18f,
                modifier = Modifier.fillMaxSize(),
            )
        }
        Canvas(Modifier.fillMaxSize()) {
            val span = maxOf(size.width, size.height)
            drawCircle(
                color = violetBloom.copy(alpha = if (dark) .17f else .09f),
                radius = span * .58f,
                center = Offset(size.width * .94f, -span * .08f),
            )
            drawCircle(
                color = tealBloom.copy(alpha = if (dark) .12f else .07f),
                radius = span * .48f,
                center = Offset(-span * .10f, size.height * .42f),
            )
            drawCircle(
                color = mint.copy(alpha = if (dark) .07f else .05f),
                radius = span * .33f,
                center = Offset(size.width * .78f, size.height * .86f),
            )
            if (backgroundStyle == AppBackgroundStyle.NightCity) {
                val building = Color(0xFF15233D).copy(alpha = if (dark) .62f else .18f)
                val glow = Color(0xFF9B7BFF).copy(alpha = if (dark) .32f else .18f)
                (0..8).forEach { index ->
                    val width = size.width * (.06f + (index % 3) * .025f)
                    val height = size.height * (.12f + (index % 5) * .035f)
                    val left = size.width * index / 9f
                    drawRect(building, topLeft = Offset(left, size.height - height), size = androidx.compose.ui.geometry.Size(width, height))
                    drawLine(glow, Offset(left + width * .15f, size.height - height + 9f), Offset(left + width * .85f, size.height - height + 9f), strokeWidth = 2f)
                }
            }
        }
        content()
        if (tapBubbles.isNotEmpty()) {
            Canvas(Modifier.fillMaxSize()) {
                tapBubbles.forEach { bubble ->
                    drawCircle(
                        color = mint.copy(alpha = .24f),
                        radius = 38.dp.toPx(),
                        center = bubble.origin,
                    )
                    drawCircle(
                        color = Color.White.copy(alpha = .24f),
                        radius = 16.dp.toPx(),
                        center = bubble.origin,
                    )
                }
            }
        }
    }
}

/** Decode a gallery background at display size so a camera photo cannot make the UI stutter or OOM. */
private fun decodeCustomBackground(context: android.content.Context, uri: Uri): android.graphics.Bitmap? {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    context.contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, bounds) }
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
    val largest = maxOf(bounds.outWidth, bounds.outHeight)
    var sample = 1
    while (largest / sample > 1440) sample *= 2
    val options = BitmapFactory.Options().apply {
        inSampleSize = sample
        inPreferredConfig = android.graphics.Bitmap.Config.RGB_565
    }
    return context.contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, options) }
}

@Composable
private fun V2GlassPanel(
    modifier: Modifier = Modifier,
    accent: Color = Aurora.Mint,
    content: @Composable () -> Unit,
) {
    Surface(
        color = Color.Transparent,
        contentColor = Aurora.Text,
        border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border.copy(alpha = .86f)),
        shape = RoundedCornerShape(22.dp),
        shadowElevation = 0.dp,
        modifier = modifier,
    ) {
        Box(
            Modifier.background(
                Brush.verticalGradient(
                    listOf(
                        Aurora.Glass.copy(alpha = .96f),
                        Aurora.VioletNight.copy(alpha = .74f),
                        accent.copy(alpha = .055f),
                    ),
                ),
            ),
        ) {
            content()
        }
    }
}

@Composable
private fun V2AuroraHeader(
    title: String,
    subtitle: String,
    status: String? = null,
    statusPositive: Boolean = true,
) {
    V2GlassPanel(modifier = Modifier.fillMaxWidth(), accent = if (statusPositive) Aurora.Mint else Aurora.Danger) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.headlineMedium, color = Aurora.Text, fontWeight = FontWeight.Bold)
                Text(subtitle, color = Aurora.Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 3.dp))
            }
            if (!status.isNullOrBlank()) {
                Surface(
                    color = (if (statusPositive) Aurora.Mint else Aurora.Danger).copy(alpha = .13f),
                    border = androidx.compose.foundation.BorderStroke(
                        1.dp,
                        (if (statusPositive) Aurora.Mint else Aurora.Danger).copy(alpha = .62f),
                    ),
                    shape = RoundedCornerShape(999.dp),
                ) {
                    Text(
                        "● $status",
                        color = if (statusPositive) Aurora.Mint else Aurora.Danger,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                    )
                }
            }
        }
    }
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
    // Probing every server on a screen where its result is invisible wastes
    // radio time and can make lower-end phones feel less responsive. Keep
    // live pings on the home/server pages and stop the worker elsewhere.
    LaunchedEffect(tab, pingItems) {
        if (tab != V2Tab.Home && tab != V2Tab.Servers) {
            offlinePings = emptyMap()
            return@LaunchedEffect
        }
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
    CompositionLocalProvider(
        LocalAuroraDark provides dark,
        LocalAuroraAccent provides adaptiveAccent,
        LocalAuroraBackgroundStyle provides state.settings.appBackgroundStyle,
        LocalAuroraCustomBackground provides state.settings.customBackgroundUri.takeIf { it.isNotBlank() },
        LocalAuroraTouchBubbles provides state.settings.touchBubblesEnabled,
    ) {
    // V2BottomBar owns the navigation-bar inset. Applying safeDrawingPadding here
    // as well reserved the bottom inset twice and lifted the controls above the
    // Android system buttons.
    Surface(color = Aurora.Night, modifier = Modifier.fillMaxSize().statusBarsPadding()) {
        if (policy.maintenance) {
            V2MaintenanceScreen(policy.maintenanceMessage)
            return@Surface
        }
        if (!state.settings.onboardingCompleted && state.initialized) {
            V2OnboardingScreen(
                hasServers = groups.any { it.items.isNotEmpty() },
                updateState = updateState,
                onLoadServers = { viewModel.installManagedSubscription() },
                onFinished = { viewModel.completeOnboarding() },
            )
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
                        onCards = { tab = V2Tab.Cards },
                    )
                    V2Tab.Servers -> V2Servers(groups, mainGroup?.tag, mainGroup?.selected, offlinePings, onSelectServer, activeProfile?.id, reliabilityScores, activeProfile?.updatedAtEpochMillis, state.busy) { viewModel.refreshAllSubscriptionsQuietly() }
                    V2Tab.Statistics -> V2Statistics(
                        stats = sessionStats,
                        connected = connected,
                        history = trafficHistory,
                        switchHistory = switchHistory,
                        diagnostics = diagnostics,
                        cumulativeBlocked = state.settings.cumulativeBlocked,
                        showTimeline = policy.features.timeline,
                    )
                    V2Tab.Settings -> V2Settings(
                        diagnostics = diagnostics,
                        policy = policy,
                        privacyScore = privacyScore,
                        vpnConnected = connected,
                        theme = state.settings.themeMode,
                        dynamicColor = state.settings.useDynamicColor,
                        autoConnect = state.settings.autoConnectOnCellular,
                        notifications = !state.settings.quietMode,
                        protectUnknownWifi = state.settings.protectUnknownWifi,
                        travelMode = state.settings.travelModeEnabled,
                        backgroundStyle = state.settings.appBackgroundStyle,
                        customBackgroundUri = state.settings.customBackgroundUri,
                        touchBubblesEnabled = state.settings.touchBubblesEnabled,
                        onTheme = viewModel::setTheme,
                        onDynamicColor = viewModel::setUseDynamicColor,
                        onAutoConnect = viewModel::setAutoConnectOnCellular,
                        onNotifications = { enabled -> viewModel.setQuietMode(!enabled) },
                        onProtectUnknownWifi = viewModel::setProtectUnknownWifi,
                        onTravelMode = viewModel::setTravelModeEnabled,
                        onBackgroundStyle = viewModel::setAppBackgroundStyle,
                        onCustomBackgroundUri = viewModel::setCustomBackgroundUri,
                        onTouchBubbles = viewModel::setTouchBubblesEnabled,
                        adBlock = state.settings.adBlockEnabled,
                        killSwitch = state.settings.blockNonVpnTraffic,
                        onAdBlock = viewModel::setAdBlockEnabled,
                        onKillSwitch = viewModel::setBlockNonVpnTraffic,
                        onCheckUpdate = onCheckUpdate,
                    )
                    V2Tab.Cards -> V2Cards(onBack = { tab = V2Tab.Home })
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
                            ?: "https://pecaocek.ignorelist.com:8443/update"
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

@Composable
private fun V2OnboardingScreen(
    hasServers: Boolean,
    updateState: UpdateState,
    onLoadServers: () -> Unit,
    onFinished: () -> Unit,
) {
    val context = LocalContext.current
    var networkOnline by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        while (true) {
            val manager = context.getSystemService(ConnectivityManager::class.java)
            val capabilities = manager?.activeNetwork?.let(manager::getNetworkCapabilities)
            networkOnline = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
            kotlinx.coroutines.delay(1_500)
        }
    }
    val updateReady = when (updateState) {
        is UpdateState.UpToDate, is UpdateState.Ready, is UpdateState.Available -> true
        else -> false
    }
    val checks = listOf(
        Triple("Сеть", if (networkOnline) "Соединение доступно" else "Проверяем интернет…", networkOnline),
        Triple("Серверы", if (hasServers) "Серверы готовы к выбору" else "Загружаем список серверов…", hasServers),
        Triple("Обновление", if (updateReady) "Версия приложения актуальна" else "Проверяем обновления…", updateReady),
    )
    val ready = checks.all { it.third }
    val progress = checks.count { it.third }.toFloat() / checks.size.toFloat()
    val progressPercent = (progress * 100f).toInt()
    Column(
        Modifier.fillMaxSize()
            .background(Brush.verticalGradient(listOf(Color(0xFF061B2B), Aurora.Night)))
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        V2BrandHeader("Защита соединения")
        Spacer(Modifier.height(4.dp))
        Box(contentAlignment = Alignment.Center, modifier = Modifier.size(244.dp)) {
            CircularProgressIndicator(
                progress = { progress.coerceAtLeast(0.06f) },
                color = Aurora.Mint,
                trackColor = Aurora.Border.copy(alpha = .48f),
                strokeWidth = 11.dp,
                modifier = Modifier.size(222.dp),
            )
            Surface(
                color = Aurora.Glass.copy(alpha = .84f),
                border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Violet.copy(alpha = .72f)),
                shape = RoundedCornerShape(58.dp),
                modifier = Modifier.size(150.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(Icons.Default.Lock, null, tint = Aurora.Mint, modifier = Modifier.size(58.dp))
                }
            }
            Text("$progressPercent%", color = Aurora.Text, fontSize = 25.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 208.dp))
        }
        Spacer(Modifier.height(14.dp))
        Text(if (ready) "Готово" else "Загружаем серверы…", color = Aurora.Text, fontSize = 23.sp, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center)
        Text("Проверяем сеть, серверы и обновления", color = Aurora.Muted, fontSize = 13.sp, textAlign = TextAlign.Center, modifier = Modifier.padding(top = 7.dp))
        Spacer(Modifier.height(20.dp))
        Surface(
            color = Aurora.Glass.copy(alpha = .88f),
            border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Mint.copy(alpha = .55f)),
            shape = RoundedCornerShape(24.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(Modifier.padding(18.dp)) {
                checks.forEachIndexed { index, item ->
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(vertical = 7.dp)) {
                        Surface(
                            shape = CircleShape,
                            color = if (item.third) Aurora.Mint.copy(alpha = .18f) else Aurora.Violet.copy(alpha = .22f),
                            modifier = Modifier.size(34.dp),
                        ) { Box(contentAlignment = Alignment.Center) { Text(if (item.third) "✓" else "${index + 1}", color = if (item.third) Aurora.Mint else Aurora.Muted, fontWeight = FontWeight.Bold) } }
                        Column(Modifier.padding(start = 12.dp)) {
                            Text(item.first, color = Aurora.Text, fontWeight = FontWeight.SemiBold)
                            Text(item.second, color = Aurora.Muted, fontSize = 12.sp)
                        }
                    }
                    if (index < checks.lastIndex) androidx.compose.material3.HorizontalDivider(color = Aurora.Border.copy(alpha = .45f))
                }
            }
        }
        Spacer(Modifier.height(22.dp))
        when {
            !hasServers -> Button(
                onClick = onLoadServers,
                colors = ButtonDefaults.buttonColors(containerColor = Aurora.Mint, contentColor = Aurora.Night),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Загрузить серверы", fontWeight = FontWeight.Bold) }
            !ready -> Text("Проверка продолжается автоматически…", color = Aurora.Muted, fontSize = 13.sp)
            else -> Button(
                onClick = onFinished,
                colors = ButtonDefaults.buttonColors(containerColor = Aurora.Mint, contentColor = Aurora.Night),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Начать пользоваться", fontWeight = FontWeight.Bold) }
        }
        TextButton(onClick = onFinished, modifier = Modifier.padding(top = 4.dp)) { Text("Пропустить проверку", color = Aurora.Muted) }
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
    onConnect: () -> Unit, onServers: () -> Unit, onSettings: () -> Unit, onCards: () -> Unit,
) {
    val stateText = when {
        connected -> "Защищено"
        busy -> "Подключение…"
        else -> "Не защищено"
    }
    val stateHint = when {
        connected -> "Ваш трафик проходит через защищённый канал"
        busy -> "Проверяем сеть и устанавливаем соединение…"
        else -> "Нажмите кнопку, чтобы включить защиту"
    }
    val stateColor = when {
        connected -> Color(0xFF54F4CF)
        busy -> Color(0xFFC395FF)
        else -> Aurora.Danger
    }
    val actionLabel = when {
        connected -> "Отключить"
        busy -> "Подключение…"
        else -> "Подключить"
    }
    Box(Modifier.fillMaxSize()) {
        AuroraGlassBackdrop(Modifier.fillMaxSize(), motionEnabled = !busy)
        Column(
            Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp, vertical = 10.dp)
                .padding(bottom = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                AuroraBrandMark(connected = connected, modifier = Modifier.size(34.dp))
                Column(Modifier.weight(1f).padding(start = 8.dp)) {
                    Text(policy.branding.name, color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                    Text(
                        policy.branding.tagline.ifBlank { "Свобода без границ" },
                        color = Color(0xFFB4C7DD),
                        fontSize = 10.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                Surface(
                    onClick = onCards,
                    shape = CircleShape,
                    color = Color(0xFF152344).copy(alpha = .86f),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFFC395FF).copy(alpha = .42f)),
                    modifier = Modifier.size(34.dp),
                ) {
                    Box(contentAlignment = Alignment.Center) { Text("♠", color = Color(0xFFCDA4FF), fontSize = 18.sp, fontWeight = FontWeight.Bold) }
                }
                Spacer(Modifier.width(7.dp))
                Surface(
                    onClick = onSettings,
                    shape = CircleShape,
                    color = Color(0xFF152344).copy(alpha = .86f),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Color.White.copy(alpha = .13f)),
                    modifier = Modifier.size(34.dp),
                ) {
                    Box(contentAlignment = Alignment.Center) { Icon(Icons.Default.Settings, null, tint = Color(0xFF6AF7D0), modifier = Modifier.size(19.dp)) }
                }
            }
            Spacer(Modifier.height(7.dp))
            AuroraStatusPill(stateText = stateText, stateColor = stateColor, subtitle = stateHint)
            Spacer(Modifier.height(6.dp))
            AuroraConnectButton(
                connected = connected,
                busy = busy,
                enabled = !busy,
                reduceMotion = busy,
                actionLabel = actionLabel,
                compact = true,
                onClick = onConnect,
            )
            Spacer(Modifier.height(7.dp))
            AuroraGlass(
                modifier = Modifier.fillMaxWidth().clickable(onClick = onServers),
                tint = Color(0xFF0E2A42),
            ) {
                Row(Modifier.padding(horizontal = 14.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(serverFlag(server), fontSize = 22.sp)
                    Column(Modifier.weight(1f).padding(start = 10.dp, end = 7.dp)) {
                        Text("Сервер", color = Color(0xFFB4C7DD), fontSize = 12.sp)
                        Text(server, color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 15.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    Surface(
                        color = if (ping != null) Color(0xFF0B594B).copy(alpha = .75f) else Color(0xFF4A2133).copy(alpha = .76f),
                        shape = RoundedCornerShape(14.dp),
                    ) {
                        Text(
                            ping?.let { "$it мс" } ?: "Таймаут",
                            color = if (ping != null) Color(0xFF5CF5D0) else Aurora.Danger,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 11.sp,
                            modifier = Modifier.padding(horizontal = 9.dp, vertical = 6.dp),
                        )
                    }
                    Text("›", color = Color.White.copy(alpha = .72f), fontSize = 22.sp, modifier = Modifier.padding(start = 7.dp))
                }
            }
            Spacer(Modifier.height(8.dp))
            AuroraGlass(
                modifier = Modifier.fillMaxWidth(),
                cornerRadius = 18.dp,
                tint = Color(0xFF102540),
            ) {
                Row(
                    Modifier.fillMaxWidth().padding(vertical = 9.dp, horizontal = 6.dp),
                    horizontalArrangement = Arrangement.SpaceEvenly,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    V2HomeStat("⌁", ping?.let { "$it мс" } ?: "Таймаут", "Пинг", if (ping != null) Color(0xFF5CF5D0) else Aurora.Danger)
                    V2HomeStat("↓", stats.samples.lastOrNull()?.let { formatBytes(it.downloadBytesPerSecond) + "/с" } ?: "—", "Загрузка", Color(0xFF5CF5D0))
                    V2HomeStat("◈", "$privacyScore/100", "Защита", Color(0xFFC395FF))
                }
            }
            AuroraGlass(modifier = Modifier.fillMaxWidth(), cornerRadius = 20.dp, tint = Color(0xFF103145)) {
                Row(
                    Modifier.padding(horizontal = 13.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(if (adBlock) "◌" else "○", color = if (adBlock) Color(0xFF5CF5D0) else Color(0xFFB4C7DD), fontSize = 18.sp)
                    Column(Modifier.weight(1f).padding(start = 8.dp)) {
                        Text("DNS и блокировка рекламы", color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
                        Text(if (adBlock && connected) "Активны" else if (adBlock) "Включатся с VPN" else "Отключены", color = Color(0xFFB4C7DD), fontSize = 10.sp)
                    }
                    Text(if (adBlock) "ВКЛ" else "ВЫКЛ", color = if (adBlock) Color(0xFF5CF5D0) else Color(0xFFB4C7DD), fontWeight = FontWeight.Bold, fontSize = 11.sp)
                }
            }
            if (!hasProfile) {
                Text("Загружаем встроенный список серверов…", color = Color(0xFF5CF5D0), fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
            }
        }
    }
}

/**
 * A deliberately small two-person lobby. The panel stores a PBKDF2 hash of
 * the access code; the APK never receives the panel administrator password.
 */
@Composable
private fun V2Cards(onBack: () -> Unit) {
    val context = LocalContext.current
    val repository = remember(context) { CardTableRepository(context) }
    val scope = rememberCoroutineScope()
    var accessCode by rememberSaveable { mutableStateOf("") }
    var displayName by rememberSaveable { mutableStateOf("") }
    var snapshot by remember { mutableStateOf<CardTableSnapshot?>(null) }
    var joining by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    // The server is the source of truth for hands and turns. Polling stops as
    // soon as a match finishes and is cancelled when the screen is left.
    LaunchedEffect(snapshot?.ticket, snapshot?.gamePhase) {
        val ticket = snapshot?.ticket ?: return@LaunchedEffect
        if (snapshot?.gamePhase == "finished") return@LaunchedEffect
        while (true) {
            kotlinx.coroutines.delay(if (snapshot?.waiting == true) 5_000 else 2_500)
            repository.state(ticket).onSuccess { refreshed ->
                // Older panel builds omitted ticket from state polling.  Keep
                // the current device-bound ticket as a compatibility guard so
                // the coroutine cannot silently stop after a guest joins.
                snapshot = refreshed.copy(ticket = refreshed.ticket.ifBlank { ticket })
                error = null
            }.onFailure { failure ->
                error = failure.message ?: "Не удалось обновить состояние стола"
            }
        }
    }

    V2AuroraBackdrop(Modifier.fillMaxSize()) {
        Column(
            Modifier.fillMaxSize().padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            V2AuroraHeader(
                title = "Игры",
                subtitle = "Дурак с друзьями · только виртуальные Q-coins",
                status = if (snapshot?.ready == true) "Игрок найден" else "Лобби",
                statusPositive = true,
            )
            snapshot?.let { table ->
                V2GlassPanel(modifier = Modifier.fillMaxWidth(), accent = Color(0xFFFFC857)) {
                    Row(
                        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("Q", color = Color(0xFFFFD36E), fontWeight = FontWeight.Black, fontSize = 22.sp)
                        Column(Modifier.weight(1f).padding(start = 10.dp)) {
                            Text("${table.qCoins} Q-coins", color = Aurora.Text, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                            Text("Виртуальные игровые очки · без вывода и покупок", color = Aurora.Muted, fontSize = 10.sp)
                        }
                        Text("♠", color = Color(0xFFC395FF), fontSize = 26.sp)
                    }
                }
            }
            if (snapshot == null) {
                V2GlassPanel(modifier = Modifier.fillMaxWidth(), accent = Color(0xFFC395FF)) {
                    Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text("Дурак с друзьями", color = Aurora.Text, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                        Text(
                            "Введите код доступа, созданный владельцем в Quantum Control. Это не пароль администратора панели.",
                            color = Aurora.Muted,
                            fontSize = 12.sp,
                        )
                        OutlinedTextField(
                            value = displayName,
                            onValueChange = { displayName = it.take(24) },
                            singleLine = true,
                            label = { Text("Ваше имя") },
                            modifier = Modifier.fillMaxWidth(),
                        )
                        OutlinedTextField(
                            value = accessCode,
                            onValueChange = { accessCode = it.take(80) },
                            singleLine = true,
                            label = { Text("Код доступа") },
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Button(
                            onClick = {
                                error = null
                                joining = true
                                scope.launch {
                                    repository.join(accessCode, displayName)
                                        .onSuccess { result ->
                                            snapshot = result
                                            accessCode = ""
                                        }
                                        .onFailure { failure -> error = failure.message ?: "Не удалось войти за стол" }
                                    joining = false
                                }
                            },
                            enabled = !joining && displayName.trim().length >= 2 && accessCode.length >= 8,
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF8B5CF6), contentColor = Color.White),
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            if (joining) CircularProgressIndicator(color = Color.White, strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
                            else Text("Войти и найти игрока")
                        }
                    }
                }
            } else {
                val table = snapshot!!
                fun play(action: String, card: String = "") {
                    joining = true
                    error = null
                    scope.launch {
                        repository.action(table.ticket, action, card)
                            .onSuccess { snapshot = it }
                            .onFailure { error = it.message ?: "Не удалось выполнить ход" }
                        joining = false
                    }
                }
                V2GlassPanel(modifier = Modifier.fillMaxWidth(), accent = if (table.ready) Aurora.Mint else Color(0xFFC395FF)) {
                    Column(Modifier.padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text(if (table.ready) "♠  Стол готов" else "♠  Ожидаем игрока", color = if (table.ready) Aurora.Mint else Color(0xFFCDA4FF), fontSize = 24.sp, fontWeight = FontWeight.Bold)
                        Text("Привет, ${table.name}!", color = Aurora.Text, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                        Text(table.message, color = Aurora.Muted, textAlign = TextAlign.Center, fontSize = 13.sp)
                        if (table.stakeQCoins > 0 && table.gamePhase != "finished") {
                            Text("Виртуальная ставка: ${table.stakeQCoins} Q-coins с игрока", color = Color(0xFFFFD36E), fontSize = 11.sp)
                        }
                        if (table.opponentName.isNotBlank()) {
                            Surface(color = Aurora.Mint.copy(alpha = .12f), shape = RoundedCornerShape(14.dp)) {
                                Text("Ваш соперник: ${table.opponentName}", color = Aurora.Mint, modifier = Modifier.padding(horizontal = 14.dp, vertical = 9.dp), fontWeight = FontWeight.SemiBold)
                            }
                            when (table.gamePhase) {
                                "ready" -> {
                                    Text(
                                        "Подтвердите готовность. Раздача начнётся, когда подтвердит второй игрок.",
                                        color = Aurora.Muted,
                                        textAlign = TextAlign.Center,
                                        fontSize = 11.sp,
                                    )
                                    Button(
                                        onClick = { play("ready") },
                                        enabled = table.canReady && !joining,
                                        colors = ButtonDefaults.buttonColors(containerColor = Aurora.Mint, contentColor = Aurora.Night),
                                    ) { Text(if (table.canReady) "Готов к раздаче" else "Ждём второго игрока") }
                                }
                                "playing" -> V2DurakTablePreview(table = table, busy = joining, onAction = ::play)
                                "finished" -> {
                                    Text(
                                        if (table.winner == table.seat) "Вы выиграли: +${table.winnerRewardQCoins} Q-coins" else "Партия завершена. Победил ${table.opponentName}. Ставка ${table.stakeQCoins} Q-coins переведена победителю.",
                                        color = if (table.winner == table.seat) Aurora.Mint else Aurora.Muted,
                                        textAlign = TextAlign.Center,
                                        fontWeight = FontWeight.SemiBold,
                                    )
                                }
                            }
                        } else {
                            CircularProgressIndicator(color = Color(0xFFCDA4FF), strokeWidth = 3.dp, modifier = Modifier.size(34.dp))
                            Text("Проверяем стол каждые 5 секунд", color = Aurora.Muted, fontSize = 11.sp)
                        }
                        Text("Стол #${table.tableId.uppercase()}", color = Aurora.Muted, fontSize = 11.sp)
                    }
                }
            }
            error?.let { message ->
                V2GlassPanel(modifier = Modifier.fillMaxWidth(), accent = Aurora.Danger) {
                    Text(message, color = Aurora.Danger, fontSize = 12.sp, modifier = Modifier.padding(14.dp))
                }
            }
            TextButton(onClick = onBack, modifier = Modifier.align(Alignment.CenterHorizontally)) {
                Text("← На главную", color = Aurora.Mint)
            }
        }
    }
}

/** Compact visual table backed by server-authoritative cards and turn checks. */
@Composable
private fun V2DurakTablePreview(table: CardTableSnapshot, busy: Boolean, onAction: (String, String) -> Unit) {
    Surface(
        color = Aurora.Night.copy(alpha = .36f),
        border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border.copy(alpha = .62f)),
        shape = RoundedCornerShape(18.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(14.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Text("Дурак с друзьями", color = Aurora.Text, fontWeight = FontWeight.Bold, fontSize = 15.sp)
            Text(
                if (table.canAttack) "Ваш ход: атакуйте" else if (table.canDefend) "Ваш ход: отбейте карту" else "Ход соперника",
                color = if (table.canAttack || table.canDefend) Aurora.Mint else Aurora.Muted,
                fontSize = 11.sp,
                modifier = Modifier.padding(top = 2.dp),
            )
            Text("Козырь ${durakCardLabel(table.trump)} · колода ${table.deckCount}", color = Aurora.Muted, fontSize = 10.sp, modifier = Modifier.padding(top = 3.dp))
            if (table.tableCards.isNotEmpty()) {
                Row(
                    Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(top = 10.dp),
                    horizontalArrangement = Arrangement.spacedBy(7.dp),
                ) {
                    table.tableCards.forEach { pair ->
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            V2DurakCard(pair.attack, enabled = false) {}
                            if (pair.defense.isNotBlank()) {
                                Spacer(Modifier.height(3.dp))
                                V2DurakCard(pair.defense, enabled = false) {}
                            }
                        }
                    }
                }
            }
            Text("Соперник · ${table.opponentCards} карт", color = Aurora.Muted, fontSize = 10.sp, modifier = Modifier.padding(top = 11.dp))
            Row(
                Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(top = 7.dp),
                horizontalArrangement = Arrangement.spacedBy(7.dp),
            ) {
                table.hand.forEach { card ->
                    V2DurakCard(
                        card = card,
                        enabled = !busy && (table.canAttack || table.canDefend),
                    ) {
                        onAction(if (table.canAttack) "attack" else "defend", card)
                    }
                }
            }
            if (table.canTake || table.canPass) {
                Row(Modifier.fillMaxWidth().padding(top = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (table.canTake) {
                        Button(
                            onClick = { onAction("take", "") },
                            enabled = !busy,
                            colors = ButtonDefaults.buttonColors(containerColor = Aurora.Violet, contentColor = Color.White),
                            modifier = Modifier.weight(1f),
                        ) { Text("Беру") }
                    }
                    if (table.canPass) {
                        Button(
                            onClick = { onAction("pass", "") },
                            enabled = !busy,
                            colors = ButtonDefaults.buttonColors(containerColor = Aurora.Mint, contentColor = Aurora.Night),
                            modifier = Modifier.weight(1f),
                        ) { Text("Передать ход") }
                    }
                }
            }
            Text("Q-coins виртуальные: без оплаты, вывода и влияния на VPN.", color = Aurora.Muted, textAlign = TextAlign.Center, fontSize = 10.sp, modifier = Modifier.padding(top = 10.dp))
        }
    }
}

@Composable
private fun V2DurakCard(card: String, enabled: Boolean, onClick: () -> Unit) {
    val label = durakCardLabel(card)
    val red = label.contains('♥') || label.contains('♦')
    Surface(
        onClick = onClick,
        enabled = enabled,
        color = if (enabled) Color(0xFFF7FBFF) else Color(0xFFDCE8F3),
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier.size(width = 42.dp, height = 58.dp),
    ) {
        Text(label, color = if (red) Color(0xFFC33861) else Color(0xFF142638), fontWeight = FontWeight.Bold, fontSize = 11.sp, modifier = Modifier.padding(6.dp))
    }
}

private fun durakCardLabel(card: String): String {
    if (card.length < 2) return "?"
    val suit = when (card.last()) { 'S' -> '♠'; 'H' -> '♥'; 'D' -> '♦'; 'C' -> '♣'; else -> '?' }
    return card.dropLast(1) + " " + suit
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
    var allServersOpen by rememberSaveable { mutableStateOf(false) }
    val allServers = groups.flatMap { it.items }
    val livePings = allServers.count { it.pingMillis != null || offlinePings[it.tag] != null }
    val updatedLabel = updatedAt?.let {
        "Список обновлён " + java.text.SimpleDateFormat("dd.MM HH:mm", java.util.Locale.getDefault()).format(java.util.Date(it))
    } ?: "Загружаем встроенный список…"
    fun reliability(server: com.quantumvpn.vpn.RuntimeOutboundItem): Int {
        val owner = groups.firstOrNull { group -> group.items.any { it.tag == server.tag } }
        val key = if (profileId != null && owner != null) {
            DeadServerQuarantineStore.serverKey(profileId, owner.tag, server.tag)
        } else server.tag
        return reliabilityScores[key] ?: reliabilityScores[server.tag] ?: 50
    }
    val rankedServers = allServers.sortedWith(
        compareByDescending<com.quantumvpn.vpn.RuntimeOutboundItem> { it.tag == selected }
            .thenBy { it.pingMillis ?: offlinePings[it.tag] ?: Int.MAX_VALUE }
            .thenByDescending(::reliability),
    )
    val quickServers = rankedServers.take(4)
    if (allServersOpen) {
        AlertDialog(
            onDismissRequest = { allServersOpen = false },
            title = { Text("Все серверы · ${rankedServers.size}") },
            text = {
                Column(Modifier.heightIn(max = 380.dp).verticalScroll(rememberScrollState())) {
                    rankedServers.forEach { server ->
                        val ping = server.pingMillis ?: offlinePings[server.tag]
                        val selectedServer = server.tag == selected
                        Surface(
                            onClick = {
                                groups.firstOrNull { group -> group.items.any { it.tag == server.tag } }
                                    ?.let { onSelect(it.tag, server.tag) }
                                allServersOpen = false
                            },
                            color = if (selectedServer) Aurora.Mint.copy(alpha = .16f) else Aurora.Glass,
                            border = androidx.compose.foundation.BorderStroke(1.dp, if (selectedServer) Aurora.Mint else Aurora.Border),
                            shape = RoundedCornerShape(14.dp),
                            modifier = Modifier.fillMaxWidth().padding(bottom = 7.dp),
                        ) {
                            Row(Modifier.padding(horizontal = 10.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                                Text(serverFlag(server.tag), fontSize = 18.sp)
                                Column(Modifier.weight(1f).padding(start = 8.dp, end = 6.dp)) {
                                    Text(server.tag, color = Aurora.Text, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    Text(server.type.uppercase(), color = Aurora.Muted, fontSize = 10.sp)
                                }
                                Text(ping?.let { "$it мс" } ?: "Таймаут", color = if (ping == null) Aurora.Danger else Aurora.Mint, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { allServersOpen = false }) { Text("Готово") } },
        )
    }
    V2AuroraBackdrop(Modifier.fillMaxSize()) {
        Column(
            Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp, vertical = 10.dp)
                .padding(bottom = 8.dp),
        ) {
            V2AuroraHeader(
                title = "Серверы",
                subtitle = "$updatedLabel · пинг обновляется каждые 20 секунд",
                status = if (allServers.isEmpty()) "ОЖИДАНИЕ" else "$livePings/${allServers.size}",
                statusPositive = allServers.isNotEmpty() && livePings > 0,
            )
            V2GlassPanel(
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                accent = Aurora.Violet,
            ) {
                Row(Modifier.padding(horizontal = 14.dp, vertical = 9.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("◉", color = Aurora.Mint, fontSize = 18.sp)
                    Text("Быстрый выбор · ${allServers.size} серверов", color = Aurora.Text, fontSize = 12.sp, modifier = Modifier.weight(1f).padding(start = 8.dp))
                    TextButton(onClick = onRefresh, enabled = !busy, contentPadding = PaddingValues(horizontal = 4.dp)) {
                        Text(if (busy) "…" else "Обновить", color = Aurora.Mint, fontSize = 11.sp)
                    }
                }
            }
            Spacer(Modifier.height(8.dp))
            if (quickServers.isEmpty()) {
                V2GlassPanel(modifier = Modifier.fillMaxWidth(), accent = Aurora.Danger) {
                    Column(Modifier.padding(14.dp)) {
                        Text("Серверы не найдены", color = Aurora.Text, fontWeight = FontWeight.SemiBold)
                        Text("Обновите встроенную подписку или проверьте подключение к сети.", color = Aurora.Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp))
                    }
                }
            }
            quickServers.forEach { server ->
                val ping = server.pingMillis ?: offlinePings[server.tag]
                val selectedServer = server.tag == selected
                Surface(
                    onClick = { groups.firstOrNull { group -> group.items.any { it.tag == server.tag } }?.let { onSelect(it.tag, server.tag) } },
                    color = if (selectedServer) Aurora.Violet.copy(alpha = .44f) else Aurora.Glass.copy(alpha = .84f),
                    border = androidx.compose.foundation.BorderStroke(
                        1.dp,
                        if (selectedServer) Aurora.Mint.copy(alpha = .84f) else Aurora.Border.copy(alpha = .88f),
                    ),
                    shape = RoundedCornerShape(18.dp),
                    modifier = Modifier.fillMaxWidth().padding(bottom = 7.dp),
                ) {
                    Row(Modifier.padding(horizontal = 12.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                        Surface(
                            color = Aurora.Night.copy(alpha = .34f),
                            shape = RoundedCornerShape(12.dp),
                        ) {
                            Text(serverFlag(server.tag), fontSize = 19.sp, modifier = Modifier.padding(6.dp))
                        }
                        Column(Modifier.weight(1f).padding(start = 9.dp, end = 6.dp)) {
                            Text(server.tag, color = Aurora.Text, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(
                                buildString {
                                    append(server.type.uppercase())
                                    if (selectedServer) append(" · выбран")
                                },
                                color = Aurora.Muted,
                                fontSize = 10.sp,
                            )
                        }
                        Surface(
                            color = if (ping != null) Aurora.Mint.copy(alpha = .13f) else Aurora.Danger.copy(alpha = .14f),
                            border = androidx.compose.foundation.BorderStroke(1.dp, if (ping != null) Aurora.Mint.copy(alpha = .68f) else Aurora.Danger.copy(alpha = .72f)),
                            shape = RoundedCornerShape(12.dp),
                        ) {
                            Text(
                                ping?.let { "$it мс · ${ServerHealthScore.combined(it, reliability(server))}" } ?: "Таймаут",
                                color = if (ping != null) Aurora.Mint else Aurora.Danger,
                                fontWeight = FontWeight.Bold,
                                fontSize = 10.sp,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
                            )
                        }
                    }
                }
            }
            if (allServers.size > quickServers.size) {
                TextButton(onClick = { allServersOpen = true }, modifier = Modifier.fillMaxWidth(), contentPadding = PaddingValues(vertical = 0.dp)) {
                    Text(
                        "Все серверы (${allServers.size}) · список обновляется автоматически",
                        color = Aurora.Mint,
                        fontSize = 10.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth(),
                    )
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
    showTimeline: Boolean,
) {
    val speed = stats.samples.lastOrNull()
    var now by remember { mutableStateOf(System.currentTimeMillis()) }
    LaunchedEffect(connected) {
        while (connected) {
            now = System.currentTimeMillis()
            kotlinx.coroutines.delay(1_000)
        }
    }
    val seconds = stats.connectedAtEpochMillis?.let { ((now - it) / 1_000).coerceAtLeast(0) } ?: 0
    val networkHealthy = diagnostics.network?.validated != false
    V2AuroraBackdrop(Modifier.fillMaxSize()) {
        Column(
            Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp, vertical = 10.dp)
                .padding(bottom = 8.dp),
        ) {
            V2AuroraHeader(
                title = "Статистика",
                subtitle = "Качество VPN-соединения в реальном времени",
                status = if (connected) "ОНЛАЙН" else "ОФЛАЙН",
                statusPositive = connected,
            )
            Spacer(Modifier.height(12.dp))
            V2GlassPanel(
                modifier = Modifier.fillMaxWidth(),
                accent = if (connected) Aurora.Mint else Aurora.Danger,
            ) {
                Row(Modifier.padding(horizontal = 13.dp, vertical = 9.dp), verticalAlignment = Alignment.CenterVertically) {
                    Surface(
                        color = (if (connected) Aurora.Mint else Aurora.Danger).copy(alpha = .14f),
                        shape = RoundedCornerShape(13.dp),
                    ) {
                        Text(if (connected) "◉" else "○", color = if (connected) Aurora.Mint else Aurora.Danger, fontSize = 20.sp, modifier = Modifier.padding(7.dp))
                    }
                    Column(Modifier.padding(start = 10.dp).weight(1f)) {
                        Text(if (connected) "Защита активна" else "Защита выключена", color = Aurora.Text, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                        Text(
                            if (connected) "Пинг и трафик обновляются автоматически" else "Подключите VPN для живой статистики",
                            color = Aurora.Muted,
                            fontSize = 10.sp,
                            modifier = Modifier.padding(top = 3.dp),
                        )
                    }
                }
            }
            Spacer(Modifier.height(12.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                V2Metric("Пинг", stats.pingMillis?.let { "$it мс" } ?: "—", Modifier.weight(1f))
                V2Metric("Загрузка", speed?.let { formatBytes(it.downloadBytesPerSecond) + "/с" } ?: "0 Б/с", Modifier.weight(1f))
            }
            Spacer(Modifier.height(10.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                V2Metric("Отдача", speed?.let { formatBytes(it.uploadBytesPerSecond) + "/с" } ?: "0 Б/с", Modifier.weight(1f))
                V2Metric("Потери", stats.pingLossPercent?.let { "$it%" } ?: "—", Modifier.weight(1f))
            }
            Spacer(Modifier.height(9.dp))
            TrafficChart(stats, compact = true)
            V2GlassPanel(modifier = Modifier.fillMaxWidth(), accent = if (networkHealthy) Aurora.Mint else Aurora.Danger) {
                Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 9.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                    V2StatisticLine("Сессия", "%02d:%02d:%02d".format(seconds / 3_600, seconds / 60 % 60, seconds % 60), modifier = Modifier.weight(1f))
                    V2StatisticLine("Трафик", formatBytes(stats.downloadTotalBytes + stats.uploadTotalBytes), modifier = Modifier.weight(1f))
                    V2StatisticLine("Реклама", "$cumulativeBlocked", accent = Aurora.Mint, modifier = Modifier.weight(1f))
                }
            }
        }
    }
}

@Composable
private fun V2StatisticLine(label: String, value: String, accent: Color = Aurora.Muted, modifier: Modifier = Modifier) {
    Column(modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Text(label, color = Aurora.Muted, fontSize = 9.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
        Text(value, color = accent, fontSize = 11.sp, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun V2Settings(
    diagnostics: DiagnosticState,
    policy: ClientPolicy,
    privacyScore: Int,
    vpnConnected: Boolean,
    theme: ThemeMode,
    dynamicColor: Boolean,
    autoConnect: Boolean,
    notifications: Boolean,
    protectUnknownWifi: Boolean,
    travelMode: Boolean,
    backgroundStyle: AppBackgroundStyle,
    customBackgroundUri: String,
    touchBubblesEnabled: Boolean,
    adBlock: Boolean,
    killSwitch: Boolean,
    onTheme: (ThemeMode) -> Unit,
    onDynamicColor: (Boolean) -> Unit,
    onAutoConnect: (Boolean) -> Unit,
    onNotifications: (Boolean) -> Unit,
    onProtectUnknownWifi: (Boolean) -> Unit,
    onTravelMode: (Boolean) -> Unit,
    onBackgroundStyle: (AppBackgroundStyle) -> Unit,
    onCustomBackgroundUri: (String) -> Unit,
    onTouchBubbles: (Boolean) -> Unit,
    onAdBlock: (Boolean) -> Unit,
    onKillSwitch: (Boolean) -> Unit,
    onCheckUpdate: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var logStatus by remember { mutableStateOf("") }
    var logConsentOpen by rememberSaveable { mutableStateOf(false) }
    var privacyOpen by rememberSaveable { mutableStateOf(false) }
    var notificationsOpen by rememberSaveable { mutableStateOf(false) }
    var aboutOpen by rememberSaveable { mutableStateOf(false) }
    var donateOpen by rememberSaveable { mutableStateOf(false) }
    var moreOpen by rememberSaveable { mutableStateOf(false) }
    var appearanceOpen by rememberSaveable { mutableStateOf(false) }
    if (appearanceOpen) {
        V2AppearancePage(
            style = backgroundStyle,
            customBackgroundUri = customBackgroundUri,
            touchBubblesEnabled = touchBubblesEnabled,
            onStyle = onBackgroundStyle,
            onCustomBackgroundUri = onCustomBackgroundUri,
            onTouchBubbles = onTouchBubbles,
            onBack = { appearanceOpen = false },
        )
        return
    }
    if (privacyOpen) {
        V2PrivacyPage(
            onBack = { privacyOpen = false },
            score = privacyScore,
            vpnConnected = vpnConnected,
            adBlock = adBlock,
            killSwitch = killSwitch,
        )
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
        V2AuroraBackdrop(Modifier.fillMaxSize()) {
            Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp).padding(bottom = 22.dp),
            ) {
            TextButton(onClick = { aboutOpen = false }) { Text("← Назад", color = Aurora.Mint) }
            V2AuroraHeader("О приложении", "QuantumVPN ${BuildConfig.VERSION_NAME}", "ПРОВЕРЕНО", true)
            Text("Aurora Glass · защита соединения", color = Aurora.Muted, modifier = Modifier.padding(top = 12.dp))
            if (policy.features.changelog) {
                Spacer(Modifier.height(22.dp))
                Text("Что нового", color = Aurora.Text, fontWeight = FontWeight.Bold)
                LocalChangelog.entries.take(3).forEach { entry ->
                    Spacer(Modifier.height(10.dp))
                    Surface(color = Aurora.Glass, border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border), shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(14.dp)) {
                            Text("Версия ${entry.version}", color = Aurora.Mint, fontWeight = FontWeight.SemiBold)
                            entry.bullets.take(3).forEach { bullet ->
                                Text("• $bullet", color = Aurora.Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 5.dp))
                            }
                        }
                    }
                }
            }
            }
        }
        return
    }
    if (moreOpen) {
        V2MoreSettingsPage(
            theme = theme,
            dynamicColor = dynamicColor,
            protectUnknownWifi = protectUnknownWifi,
            travelMode = travelMode,
            notifications = notifications,
            onTheme = onTheme,
            onDynamicColor = onDynamicColor,
            onProtectUnknownWifi = onProtectUnknownWifi,
            onTravelMode = onTravelMode,
            onNotifications = onNotifications,
            onNotificationsOpen = { notificationsOpen = true },
            onDonateOpen = { donateOpen = true },
            onAboutOpen = { aboutOpen = true },
            onPrivacyOpen = { privacyOpen = true },
            onBack = { moreOpen = false },
        )
        return
    }
    if (logConsentOpen) {
        AlertDialog(
            onDismissRequest = { logConsentOpen = false },
            title = { Text("Отправить диагностику?") },
            text = { Text("Будут отправлены только обезличенные журналы и сведения об ошибке. Пароли, ссылки подписок и содержимое трафика не отправляются.") },
            confirmButton = {
                Button(onClick = {
                    logConsentOpen = false
                    scope.launch {
                        logStatus = "Отправка…"
                        logStatus = if (VoluntaryDiagnosticReporter(context).send(diagnostics).isSuccess) "Отчёт отправлен в панель" else "Не удалось отправить отчёт"
                    }
                }) { Text("Отправить") }
            },
            dismissButton = { TextButton(onClick = { logConsentOpen = false }) { Text("Отмена") } },
        )
    }
    V2AuroraBackdrop(Modifier.fillMaxSize()) {
        Column(
            Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp, vertical = 10.dp)
                .padding(bottom = 8.dp),
        ) {
        V2AuroraHeader(
            title = "Настройки",
            subtitle = "Защита, внешний вид и управление сервисом",
            status = if (vpnConnected) "ЗАЩИТА" else "ГОТОВО",
            statusPositive = true,
        )
        Spacer(Modifier.height(8.dp))
        V2SettingsGroup("Защита") {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                V2MiniToggle("DNS и реклама", adBlock, onAdBlock, Modifier.weight(1f))
                V2MiniToggle("Kill Switch", killSwitch, onKillSwitch, Modifier.weight(1f))
            }
            Row(Modifier.fillMaxWidth().padding(top = 7.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                V2MiniToggle("Автоподключение", autoConnect, onAutoConnect, Modifier.weight(1f))
                V2MiniToggle("Уведомления", notifications, onNotifications, Modifier.weight(1f))
            }
        }
        Spacer(Modifier.height(8.dp))
        V2SettingsGroup("Оформление") {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf(ThemeMode.System, ThemeMode.Dark, ThemeMode.Light).forEach { mode ->
                    Surface(
                        onClick = { onTheme(mode) },
                        color = if (theme == mode) Aurora.Mint else Aurora.Glass,
                        border = androidx.compose.foundation.BorderStroke(1.dp, if (theme == mode) Aurora.Mint else Aurora.Border),
                        shape = RoundedCornerShape(12.dp),
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
                            fontSize = 10.sp,
                            fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.padding(vertical = 8.dp),
                        )
                    }
                }
            }
            V2MiniNav(
                "Фон и эффекты",
                onClick = { appearanceOpen = true },
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            )
        }
        Spacer(Modifier.height(8.dp))
        V2SettingsGroup("Сервис") {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                V2MiniNav("Обновление", onClick = onCheckUpdate, modifier = Modifier.weight(1f))
                V2MiniNav("Логи", onClick = { logConsentOpen = true }, modifier = Modifier.weight(1f))
                V2MiniNav("Ещё", onClick = { moreOpen = true }, modifier = Modifier.weight(1f))
            }
        }
        if (logStatus.isNotBlank()) Text(logStatus, color = Aurora.Muted, fontSize = 10.sp, modifier = Modifier.padding(top = 5.dp))
        }
    }
}

@Composable
private fun V2AppearancePage(
    style: AppBackgroundStyle,
    customBackgroundUri: String,
    touchBubblesEnabled: Boolean,
    onStyle: (AppBackgroundStyle) -> Unit,
    onCustomBackgroundUri: (String) -> Unit,
    onTouchBubbles: (Boolean) -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION,
                )
            }
            onCustomBackgroundUri(uri.toString())
            onStyle(AppBackgroundStyle.Custom)
        }
    }
    V2AuroraBackdrop(Modifier.fillMaxSize()) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp).padding(bottom = 24.dp),
        ) {
            TextButton(onClick = onBack) { Text("← Назад", color = Aurora.Mint) }
            V2AuroraHeader("Оформление", "Фоны сохраняются только на этом устройстве", "ЛОКАЛЬНО", true)
            Spacer(Modifier.height(14.dp))
            Text("Фон приложения", color = Aurora.Text, fontWeight = FontWeight.Bold, fontSize = 17.sp)
            Text("Выберите готовый стиль или свою фотографию из галереи.", color = Aurora.Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp, bottom = 10.dp))
            V2BackgroundChoice(
                title = "Северное сияние",
                subtitle = "Мятный свет и горы",
                style = AppBackgroundStyle.Aurora,
                selected = style == AppBackgroundStyle.Aurora,
                colors = listOf(Color(0xFF142B55), Color(0xFF22D9C0), Color(0xFF6C55E8)),
                onClick = { onStyle(AppBackgroundStyle.Aurora) },
            )
            Spacer(Modifier.height(8.dp))
            V2BackgroundChoice(
                title = "Город ночью",
                subtitle = "Фиолетовые огни и стекло",
                style = AppBackgroundStyle.NightCity,
                selected = style == AppBackgroundStyle.NightCity,
                colors = listOf(Color(0xFF221137), Color(0xFF4A317C), Color(0xFF0BD7E8)),
                onClick = { onStyle(AppBackgroundStyle.NightCity) },
            )
            Spacer(Modifier.height(8.dp))
            V2BackgroundChoice(
                title = "Глубокий космос",
                subtitle = "Спокойный тёмный градиент",
                style = AppBackgroundStyle.DeepSpace,
                selected = style == AppBackgroundStyle.DeepSpace,
                colors = listOf(Color(0xFF020818), Color(0xFF083A60), Color(0xFF18305C)),
                onClick = { onStyle(AppBackgroundStyle.DeepSpace) },
            )
            Spacer(Modifier.height(8.dp))
            V2GlassPanel(modifier = Modifier.fillMaxWidth(), accent = Color(0xFF8B5CF6)) {
                Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("▣", color = Color(0xFFC6A8FF), fontSize = 24.sp)
                    Column(Modifier.weight(1f).padding(start = 12.dp)) {
                        Text("Мой фон", color = Aurora.Text, fontWeight = FontWeight.SemiBold)
                        Text(
                            if (customBackgroundUri.isBlank()) "Выберите JPG, PNG или WebP" else "Фотография выбрана и хранится на телефоне",
                            color = Aurora.Muted,
                            fontSize = 11.sp,
                        )
                    }
                    TextButton(onClick = { picker.launch(arrayOf("image/*")) }) {
                        Text(if (customBackgroundUri.isBlank()) "Выбрать" else "Изменить", color = Aurora.Mint)
                    }
                }
            }
            Spacer(Modifier.height(14.dp))
            V2SettingsGroup("Эффекты") {
                V2CompactToggle("Пузырьки при касании", touchBubblesEnabled, onTouchBubbles)
                Text("Лёгкая системная ripple-анимация кнопок. Не влияет на VPN и не расходует сеть.", color = Aurora.Muted, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
            }
        }
    }
}

@Composable
private fun V2BackgroundChoice(
    title: String,
    subtitle: String,
    style: AppBackgroundStyle,
    selected: Boolean,
    colors: List<Color>,
    onClick: () -> Unit,
) {
    Surface(
        onClick = onClick,
        color = Color.Transparent,
        border = androidx.compose.foundation.BorderStroke(1.dp, if (selected) Aurora.Mint else Aurora.Border),
        shape = RoundedCornerShape(18.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            Modifier.fillMaxWidth().background(Brush.horizontalGradient(colors.map { it.copy(alpha = .6f) })).padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Surface(color = Aurora.Night.copy(alpha = .48f), shape = CircleShape, modifier = Modifier.size(40.dp)) {
                Box(contentAlignment = Alignment.Center) {
                    Text(if (selected) "✓" else "◌", color = if (selected) Aurora.Mint else Aurora.Text, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                }
            }
            Column(Modifier.weight(1f).padding(start = 12.dp)) {
                Text(title, color = Aurora.Text, fontWeight = FontWeight.Bold)
                Text(subtitle, color = Aurora.Text.copy(alpha = .78f), fontSize = 11.sp)
            }
            if (selected) Text("Выбран", color = Aurora.Mint, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
        }
    }
}

@Composable
private fun V2MoreSettingsPage(
    theme: ThemeMode,
    dynamicColor: Boolean,
    protectUnknownWifi: Boolean,
    travelMode: Boolean,
    notifications: Boolean,
    onTheme: (ThemeMode) -> Unit,
    onDynamicColor: (Boolean) -> Unit,
    onProtectUnknownWifi: (Boolean) -> Unit,
    onTravelMode: (Boolean) -> Unit,
    onNotifications: (Boolean) -> Unit,
    onNotificationsOpen: () -> Unit,
    onDonateOpen: () -> Unit,
    onAboutOpen: () -> Unit,
    onPrivacyOpen: () -> Unit,
    onBack: () -> Unit,
) {
    V2AuroraBackdrop(Modifier.fillMaxSize()) {
        Column(
            Modifier.fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp)
                .padding(bottom = 22.dp),
        ) {
            TextButton(onClick = onBack) { Text("← Назад", color = Aurora.Mint) }
            V2AuroraHeader("Дополнительные настройки", "Редкие параметры и сведения о приложении", "ГОТОВО", true)
            Spacer(Modifier.height(12.dp))
            V2SettingsGroup("Оформление и сеть") {
                V2CompactToggle("Цвета Android", dynamicColor, onDynamicColor)
                V2CompactToggle("Защита неизвестного Wi‑Fi", protectUnknownWifi, onProtectUnknownWifi)
                V2CompactToggle("Режим поездки", travelMode, onTravelMode)
                V2CompactToggle("Уведомления", notifications, onNotifications)
            }
            Spacer(Modifier.height(10.dp))
            V2SettingsGroup("Сервис") {
                V2NavRow("Центр уведомлений", "Обновления, объявления и состояние сервиса", onNotificationsOpen)
                V2NavRow("Пожертвование", "Открыть ЮMoney во внешнем браузере", onDonateOpen)
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    V2MiniNav("О приложении", onAboutOpen, Modifier.weight(1f))
                    V2MiniNav("Приватность", onPrivacyOpen, Modifier.weight(1f))
                }
            }
            Spacer(Modifier.height(16.dp))
        }
    }
}

@Composable
private fun V2NotificationCenterPage(
    policy: ClientPolicy,
    onBack: () -> Unit,
    onOpenSystemSettings: () -> Unit,
) {
    V2AuroraBackdrop(Modifier.fillMaxSize()) {
        Column(
            Modifier.fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp)
                .padding(bottom = 22.dp),
        ) {
        TextButton(onClick = onBack) { Text("← Назад", color = Aurora.Mint) }
        V2AuroraHeader(
            title = "Центр уведомлений",
            subtitle = "Обновления, состояние сервиса и важные объявления",
            status = if (policy.maintenance) "РАБОТЫ" else "ГОТОВО",
            statusPositive = !policy.maintenance,
        )
        Spacer(Modifier.height(14.dp))
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
    V2AuroraBackdrop(Modifier.fillMaxSize()) {
        Column(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp)
                .padding(bottom = 22.dp),
        ) {
        TextButton(onClick = onBack) { Text("← Назад", color = Aurora.Mint) }
        V2AuroraHeader("Пожертвование", "Поддержите QuantumVPN через ЮMoney", "ЮMONEY", true)
        Spacer(Modifier.height(14.dp))
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
private fun V2PrivacyPage(
    onBack: () -> Unit,
    score: Int,
    vpnConnected: Boolean,
    adBlock: Boolean,
    killSwitch: Boolean,
) {
    V2AuroraBackdrop(Modifier.fillMaxSize()) {
        Column(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp)
                .padding(bottom = 22.dp),
        ) {
        TextButton(onClick = onBack) { Text("← Назад", color = Aurora.Mint) }
        V2AuroraHeader("Конфиденциальность", "Данные остаются под вашим контролем", "ПРИВАТНО", true)
        Spacer(Modifier.height(14.dp))
        Surface(
            color = Aurora.Mint.copy(alpha = .12f),
            border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Mint.copy(alpha = .55f)),
            shape = RoundedCornerShape(20.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(Modifier.padding(18.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Индекс приватности", color = Aurora.Text, fontWeight = FontWeight.SemiBold)
                    Text(PrivacyScore.label(score), color = Aurora.Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp))
                }
                Text("$score/100", color = Aurora.Mint, fontSize = 25.sp, fontWeight = FontWeight.Bold)
            }
        }
        Spacer(Modifier.height(14.dp))
        listOf(
            "VPN-сессия защищена" to vpnConnected,
            "Блокировка рекламы" to adBlock,
            "Аварийное отключение" to killSwitch,
            "История сайтов и DNS-запросов не сохраняется" to true,
            "Подписки и ключи хранятся локально в Android Keystore" to true,
            "Диагностика отправляется только после нажатия кнопки" to true,
            "Отчёт очищается от ссылок, ключей и других секретов" to true,
            "Обновления APK проверяются по SHA-256 и подписи" to true,
        ).forEach { (item, enabled) ->
            V2StatusRow(item, if (enabled) "Активно" else "Можно включить в настройках", enabled)
            Spacer(Modifier.height(10.dp))
        }
        }
    }
}

@Composable
private fun V2SettingsGroup(title: String, content: @Composable () -> Unit) {
    V2GlassPanel(modifier = Modifier.fillMaxWidth(), accent = Aurora.Violet) {
        Column(Modifier.padding(13.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
                Surface(color = Aurora.Mint.copy(alpha = .16f), shape = CircleShape, modifier = Modifier.size(8.dp)) {}
                Text(title, color = Aurora.Text, fontSize = 13.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(start = 8.dp))
            }
            content()
        }
    }
}

@Composable
private fun V2CompactToggle(title: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(top = 7.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(title, color = Aurora.Text, fontSize = 12.sp, modifier = Modifier.weight(1f).padding(end = 8.dp))
        Switch(checked = checked, onCheckedChange = onChange, modifier = Modifier.height(30.dp), colors = SwitchDefaults.colors(checkedThumbColor = Aurora.Mint, checkedTrackColor = Aurora.Violet.copy(alpha = .72f)))
    }
}

@Composable
private fun V2MiniToggle(title: String, checked: Boolean, onChange: (Boolean) -> Unit, modifier: Modifier) {
    Surface(
        color = Aurora.VioletNight.copy(alpha = .50f),
        border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border.copy(alpha = .88f)),
        shape = RoundedCornerShape(16.dp),
        modifier = modifier,
    ) {
        Column(Modifier.padding(horizontal = 11.dp, vertical = 9.dp)) {
            Text(title, color = Aurora.Text, fontSize = 11.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Switch(checked = checked, onCheckedChange = onChange, modifier = Modifier.height(30.dp), colors = SwitchDefaults.colors(checkedThumbColor = Aurora.Mint, checkedTrackColor = Aurora.Violet.copy(alpha = .72f)))
        }
    }
}

@Composable
private fun V2MiniNav(title: String, onClick: () -> Unit, modifier: Modifier) {
    Surface(onClick = onClick, color = Aurora.VioletNight.copy(alpha = .50f), border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border.copy(alpha = .88f)), shape = RoundedCornerShape(16.dp), modifier = modifier.heightIn(min = 48.dp)) {
        Text(title, color = Aurora.Text, fontSize = 11.sp, textAlign = TextAlign.Center, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.fillMaxWidth().padding(vertical = 13.dp, horizontal = 6.dp))
    }
}

@Composable
private fun V2Metric(title: String, value: String, modifier: Modifier) = V2GlassPanel(modifier = modifier, accent = Aurora.Violet) {
    Column(Modifier.padding(horizontal = 14.dp, vertical = 13.dp)) {
        Text(title, color = Aurora.Muted, fontSize = 11.sp)
        Text(value, color = Aurora.Text, fontWeight = FontWeight.Bold, fontSize = 19.sp, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.padding(top = 3.dp))
    }
}

@Composable
private fun V2Toggle(title: String, subtitle: String, checked: Boolean, onChange: (Boolean) -> Unit) = V2GlassPanel(modifier = Modifier.fillMaxWidth()) {
    Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f).padding(end = 8.dp)) {
            Text(title, color = Aurora.Text, fontWeight = FontWeight.SemiBold)
            Text(subtitle, color = Aurora.Muted, fontSize = 12.sp)
        }
        Switch(checked = checked, onCheckedChange = onChange, colors = SwitchDefaults.colors(checkedThumbColor = Aurora.Mint, checkedTrackColor = Aurora.Violet.copy(alpha = .72f)))
    }
}

@Composable
private fun V2StatusRow(title: String, subtitle: String, good: Boolean) = V2GlassPanel(modifier = Modifier.fillMaxWidth(), accent = if (good) Aurora.Mint else Aurora.Danger) {
    Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(Icons.Default.CheckCircle, null, tint = if (good) Aurora.Mint else Aurora.Muted)
        Column(Modifier.padding(start = 12.dp)) {
            Text(title, color = Aurora.Text, fontWeight = FontWeight.SemiBold)
            Text(subtitle, color = Aurora.Muted, fontSize = 12.sp)
        }
    }
}

@Composable
private fun V2NavRow(title: String, subtitle: String, onClick: () -> Unit) = Surface(
    onClick = onClick,
    color = Aurora.Glass.copy(alpha = .90f),
    border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border.copy(alpha = .88f)),
    shape = RoundedCornerShape(18.dp),
    modifier = Modifier.fillMaxWidth().heightIn(min = 64.dp),
) {
    Row(Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f).padding(end = 8.dp)) {
            Text(title, color = Aurora.Text, fontWeight = FontWeight.SemiBold)
            Text(subtitle, color = Aurora.Muted, fontSize = 12.sp)
        }
        Text("›", color = Aurora.Mint, fontSize = 24.sp)
    }
}

@Composable
private fun V2BottomBar(tab: V2Tab, onTab: (V2Tab) -> Unit) = Surface(
    color = Aurora.Night.copy(alpha = .97f),
    border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border.copy(alpha = .74f)),
    shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
    shadowElevation = 14.dp,
    // Some Android/OEM builds report a bogus navigation-bar inset (hundreds of
    // dp) when edge-to-edge is enabled. A small fixed clearance keeps the bar
    // above the three Android system buttons without letting it stretch into
    // the middle of the screen.
    modifier = Modifier.fillMaxWidth().padding(bottom = 20.dp),
) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 7.dp, vertical = 7.dp),
        horizontalArrangement = Arrangement.SpaceEvenly,
    ) {
        // Cards is opened from the compact home shortcut. Keeping four fixed
        // bottom actions preserves tap targets on small Android screens.
        V2Tab.entries.filter { it != V2Tab.Cards }.forEach { item ->
            val selected = item == tab
            Surface(
                onClick = { onTab(item) },
                color = if (selected) Aurora.Mint.copy(alpha = .14f) else Color.Transparent,
                shape = RoundedCornerShape(16.dp),
                // The previous minimum-only height let fillMaxSize() in the
                // child Column consume the whole free screen height on some
                // devices.  That turned the selected tab into a tall stripe,
                // pushed the bar upward, and hid the page content.  A fixed
                // tab height keeps the complete bottom bar compact.
                modifier = Modifier.weight(1f).height(56.dp).padding(horizontal = 2.dp),
            ) {
                Column(
                    Modifier.fillMaxSize().padding(vertical = 6.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    Icon(item.icon, contentDescription = item.title, tint = if (selected) Aurora.Mint else Aurora.Muted, modifier = Modifier.size(22.dp))
                    Text(item.title, color = if (selected) Aurora.Mint else Aurora.Muted, fontSize = 10.sp, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal)
                }
            }
        }
    }
}

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
private fun TrafficChart(stats: VpnSessionStats, compact: Boolean = false) {
    val samples = stats.samples.takeLast(60)
    val mint = Aurora.Mint
    val violet = Aurora.Violet
    val border = Aurora.Border
    V2GlassPanel(modifier = Modifier.fillMaxWidth().padding(bottom = if (compact) 8.dp else 14.dp), accent = Aurora.Violet) {
        Column(Modifier.padding(if (compact) 10.dp else 16.dp)) {
            Text("Трафик", color = Aurora.Text, fontWeight = FontWeight.Bold, fontSize = if (compact) 12.sp else 14.sp)
            Text("Загрузка · Отдача", color = Aurora.Muted, fontSize = if (compact) 10.sp else 12.sp)
            if (samples.size < 2) Text("График появится после получения данных", color = Aurora.Muted, fontSize = if (compact) 10.sp else 12.sp, modifier = Modifier.padding(vertical = if (compact) 10.dp else 24.dp))
            else Canvas(Modifier.fillMaxWidth().height(if (compact) 76.dp else 130.dp).padding(top = if (compact) 8.dp else 16.dp)) {
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
