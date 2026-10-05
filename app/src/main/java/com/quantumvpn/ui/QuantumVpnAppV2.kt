package com.quantumvpn.ui

import android.graphics.BitmapFactory
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.Image
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.layout.imePadding
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
import androidx.compose.material.icons.filled.Notifications
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
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.navigationBars
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
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.Density
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.heading
import androidx.activity.compose.BackHandler
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.LifecycleOwner
import androidx.compose.runtime.DisposableEffect
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
import com.quantumvpn.community.CommunityRepository
import com.quantumvpn.community.NotificationInboxScreen
import com.quantumvpn.community.SupportCenterScreen
import com.quantumvpn.diagnostics.DiagnosticReportRedactor
import org.json.JSONObject
import com.quantumvpn.profiles.ProfilesUiState
import com.quantumvpn.profiles.ProfilesViewModel
import com.quantumvpn.vpn.RuntimeSelectorGroup
import com.quantumvpn.vpn.VpnConnectionState
import com.quantumvpn.vpn.VpnSessionStats
import com.quantumvpn.vpn.ServerHealthScore
import com.quantumvpn.vpn.DeadServerQuarantineStore
import com.quantumvpn.vpn.FavoriteServersStore
import com.quantumvpn.vpn.forServerUi
import com.quantumvpn.vpn.primaryGroup
import com.quantumvpn.vpn.UnderlyingServerPing
import com.quantumvpn.vpn.ServerSwitchEvent
import com.quantumvpn.policy.ClientPolicy

internal enum class V2Tab(val title: String, val icon: ImageVector) {
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
private val LocalAuroraReduceMotion = staticCompositionLocalOf { false }
private val LocalAuroraContrast = staticCompositionLocalOf { false }
private val LocalAuroraBackdropDrawn = staticCompositionLocalOf { false }
private val LocalAuroraHaptics = staticCompositionLocalOf { true }
private data class AuroraTapBubble(val id: Long, val origin: Offset)
private object Aurora {
    val Night: Color @Composable get() = if (LocalAuroraDark.current) Color(0xFF040B16) else Color(0xFFF3F7FB)
    val VioletNight: Color @Composable get() = if (LocalAuroraDark.current) Color(0xFF071526) else Color(0xFFE8F1FA)
    val Glass: Color @Composable get() = if (LocalAuroraDark.current) {
        if (LocalAuroraContrast.current) Color(0xFF0B1E33) else Color(0xEE0B1E33)
    } else Color(0xF5FFFFFF)
    val Mint: Color @Composable get() = if (LocalAuroraDark.current) LocalAuroraAccent.current else Color(0xFF0087A8)
    val Violet: Color @Composable get() = if (LocalAuroraDark.current) Color(0xFF9B6DFF) else Color(0xFF7055D9)
    val Text: Color @Composable get() = if (LocalAuroraDark.current) Color(0xFFF4FBFF) else Color(0xFF0B1A2A)
    val Muted: Color @Composable get() = if (LocalAuroraDark.current) {
        if (LocalAuroraContrast.current) Color(0xFFE2EEF7) else Color(0xFFABC0D4)
    } else Color(0xFF41556A)
    val Border: Color @Composable get() = if (LocalAuroraContrast.current) Aurora.Muted else if (LocalAuroraDark.current) Color(0xFF24516D) else Color(0xFFB7CDDE)
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
    // One decoded photo and one backdrop for the entire shell, not one per tab.
    if (LocalAuroraBackdropDrawn.current) {
        Box(modifier) { content() }
        return
    }
    val mint = Aurora.Mint
    val dark = LocalAuroraDark.current
    val backgroundStyle = LocalAuroraBackgroundStyle.current
    val resources = LocalAppResources.current
    val app = LocalContext.current.applicationContext as QuantumVpnApplication
    // A panel background is a default only; never replace a user-selected style/photo.
    val backgroundUri = when (backgroundStyle) {
        AppBackgroundStyle.Custom -> LocalAuroraCustomBackground.current
        AppBackgroundStyle.Aurora -> if (resources?.assets?.containsKey("background") == true) {
            app.container.appResourceRepository.imageFile("background")?.let { Uri.fromFile(it).toString() }
        } else null
        else -> null
    }
    val touchBubbles = LocalAuroraTouchBubbles.current && !LocalAuroraReduceMotion.current
    val context = LocalContext.current
    val violetBloom = if (dark) Color(0xFF8B5CF6) else Color(0xFF6D4AFF)
    val tealBloom = if (dark) Color(0xFF2EE5C8) else Color(0xFF00A58B)
    val customBitmap by produceState<android.graphics.Bitmap?>(
        initialValue = null,
        key1 = backgroundStyle,
        key2 = backgroundUri,
    ) {
        value = if (backgroundStyle in setOf(AppBackgroundStyle.Custom, AppBackgroundStyle.Aurora) && !backgroundUri.isNullOrBlank()) {
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
        if (backgroundStyle == AppBackgroundStyle.Aurora && dark && customBitmap == null) {
            AuroraGlassBackdrop(Modifier.fillMaxSize(), motionEnabled = false)
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
        CompositionLocalProvider(LocalAuroraBackdropDrawn provides true) { content() }
        tapBubbles.forEach { bubble -> V2TouchWave(bubble, mint) }
    }
}

/** Finite touch feedback: at most five 520 ms waves; no idle animation timer. */
@Composable
private fun V2TouchWave(bubble: AuroraTapBubble, color: Color) {
    val progress = remember(bubble.id) { Animatable(0f) }
    LaunchedEffect(bubble.id) { progress.animateTo(1f, tween(520)) }
    Canvas(Modifier.fillMaxSize()) {
        val fraction = progress.value
        drawCircle(color.copy(alpha = .26f * (1f - fraction)), 48.dp.toPx() * fraction, bubble.origin,
            style = Stroke(2.dp.toPx()))
        drawCircle(Color.White.copy(alpha = .17f * (1f - fraction)), 28.dp.toPx() * fraction, bubble.origin)
    }
}

/** Decode a gallery background at display size so a camera photo cannot make the UI stutter or OOM. */
private fun decodeCustomBackground(context: android.content.Context, uri: Uri): android.graphics.Bitmap? {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    context.contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, bounds) }
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
    val options = BitmapFactory.Options().apply {
        inSampleSize = backgroundSampleSize(bounds.outWidth, bounds.outHeight)
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

@Composable
private fun rememberAuroraVisible(): Boolean {
    val owner = LocalContext.current as? LifecycleOwner
    var visible by remember(owner) { mutableStateOf(owner?.lifecycle?.currentState?.isAtLeast(Lifecycle.State.STARTED) != false) }
    DisposableEffect(owner) {
        val observer = LifecycleEventObserver { _, _ ->
            visible = owner?.lifecycle?.currentState?.isAtLeast(Lifecycle.State.STARTED) != false
        }
        owner?.lifecycle?.addObserver(observer)
        onDispose { owner?.lifecycle?.removeObserver(observer) }
    }
    return visible
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
    var settingsNotificationsOpen by rememberSaveable { mutableStateOf(false) }
    // The device-bound game ticket lives in the shell, not in a transient tab.
    // Never save the ticket or an access code into an Activity bundle or disk.
    val cardSession = remember { V2CardSession() }
    val cardRequestScope = rememberCoroutineScope()
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
    val visible = rememberAuroraVisible()
    var offlinePings by remember { mutableStateOf<Map<String, Int>>(emptyMap()) }
    var offlinePingCompleted by remember { mutableStateOf(false) }
    val pingItems = remember(groups) { groups.flatMap { it.items }.distinctBy { it.tag } }
    // Runtime measurements update ping fields; they must not restart the probe
    // loop before its delay or cancel a batch still in progress.
    val pingTargets = pingItems.map { it.tag to it.endpoint }
    // Probing every server on a screen where its result is invisible wastes
    // radio time and can make lower-end phones feel less responsive. Keep
    // live pings on the home/server pages and stop the worker elsewhere.
    LaunchedEffect(tab, pingTargets, visible) {
        if (!visible || (tab != V2Tab.Home && tab != V2Tab.Servers)) {
            return@LaunchedEffect
        }
        while (true) {
            offlinePings = UnderlyingServerPing.measure(context, pingItems)
            offlinePingCompleted = true
            kotlinx.coroutines.delay(20_000)
        }
    }
    LaunchedEffect(tab, connected, mainGroup?.tag, visible) {
        if (!connected || !visible) return@LaunchedEffect
        while (tab == V2Tab.Servers || tab == V2Tab.Home) {
            mainGroup?.tag?.takeIf(String::isNotBlank)?.let(onMeasureGroup) ?: onMeasurePing()
            kotlinx.coroutines.delay(20_000)
        }
    }
    val app = context.applicationContext as QuantumVpnApplication
    val policy by app.container.clientPolicyRepository.policy.collectAsState()
    val resources by app.container.appResourceRepository.resources.collectAsState()
    LaunchedEffect(visible) {
        if (!visible) return@LaunchedEffect
        while (true) {
            app.container.appResourceRepository.refresh()
            kotlinx.coroutines.delay(300_000)
        }
    }
    val trafficHistory by viewModel.sessionTrafficHistory.collectAsState()
    val switchHistory by viewModel.switchHistory.collectAsState()
    val reliabilityScores by viewModel.reliabilityScores.collectAsState()
    val favoriteKeys by viewModel.favoriteKeys.collectAsState()
    val routingLabel by produceState(initialValue = "—", key1 = visible, key2 = state.settings.panelRoutingEnabled) {
        if (!state.settings.panelRoutingEnabled) {
            value = "Выкл"
        } else if (visible) {
            val cached = withContext(Dispatchers.IO) { app.container.remoteRoutingPolicyRepository.cached() }
            value = (cached as? com.quantumvpn.routing.RoutingPolicyRefreshResult.Applied)
                ?.verified?.policy?.revision?.let { "r$it" } ?: "—"
        }
    }
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
        if (resources?.accent != null && !state.settings.highContrast) remoteAccent(resources!!.accent!!)
        else if (policy.branding.accentHex.equals("#3DE7FF", ignoreCase = true)) Color(0xFF2CEBF1)
        else remoteAccent(policy.branding.accentHex)
    }
    val density = LocalDensity.current
    BackHandler(tab != V2Tab.Home) { tab = V2Tab.Home }
    ResourcePresentation(app.container.appResourceRepository) {
    CompositionLocalProvider(
        LocalAuroraDark provides dark,
        LocalAuroraAccent provides adaptiveAccent,
        LocalAuroraBackgroundStyle provides state.settings.appBackgroundStyle,
        LocalAuroraCustomBackground provides state.settings.customBackgroundUri.takeIf { it.isNotBlank() },
        LocalAuroraTouchBubbles provides state.settings.touchBubblesEnabled,
        LocalAuroraReduceMotion provides state.settings.reduceMotion,
        LocalAuroraContrast provides state.settings.highContrast,
        LocalAuroraHaptics provides state.settings.hapticsEnabled,
        LocalDensity provides Density(density.density, auroraFontScale(density.fontScale, state.settings.largeText)),
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
        V2AuroraBackdrop(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize()) {
            if (block != null || policy.activeAnnounce().isNotBlank()) {
                Text(block ?: policy.activeAnnounce(), color = Aurora.Text, modifier = Modifier.fillMaxWidth().background(Aurora.Glass).padding(16.dp))
            }
            if (state.message != null) Text(state.message, color = Aurora.Muted, modifier = Modifier.padding(horizontal = 16.dp))
            Box(Modifier.weight(1f)) {
                // A brief content-only fade avoids sliding controls underneath system bars.
                // Leaving composition cancels old-page workers; accessibility can disable it.
                AnimatedContent(targetState = tab, label = "quantum-page", transitionSpec = {
                    val duration = if (state.settings.reduceMotion || !visible) 0 else 150
                    fadeIn(tween(duration)) togetherWith fadeOut(tween(duration))
                }) { displayedTab ->
                when (displayedTab) {
                    V2Tab.Home -> V2Home(
                        policy = policy,
                        connected = connected,
                        busy = busy,
                        hasProfile = activeProfile != null,
                        server = selected?.tag ?: "Автоматический сервер",
                        ping = if (connected) selected?.pingMillis ?: selected?.tag?.let(offlinePings::get)
                            else selected?.tag?.let(offlinePings::get),
                        pingMeasured = offlinePingCompleted,
                        adBlock = state.settings.adBlockEnabled,
                        privacyScore = privacyScore,
                        stats = sessionStats,
                        reduceMotion = state.settings.reduceMotion,
                        onNotifications = { settingsNotificationsOpen = true; tab = V2Tab.Settings },
                        onConnect = {
                            val id = activeProfile?.id
                            if (id == null) viewModel.installManagedSubscription()
                            else if (connected) onVpnStop()
                            else if (block == null && !busy) onVpnStart(id)
                        },
                        onServers = { tab = V2Tab.Servers },
                        onSettings = { settingsNotificationsOpen = false; tab = V2Tab.Settings },
                        onCards = { tab = V2Tab.Cards },
                        dnsStatus = if (!connected) "С VPN" else if (state.settings.adBlockEnabled) "Фильтр" else "Активен",
                        routingLabel = routingLabel,
                    )
                    V2Tab.Servers -> V2Servers(
                        groups, mainGroup?.tag, mainGroup?.selected, offlinePings, onSelectServer,
                        activeProfile?.id, reliabilityScores, activeProfile?.updatedAtEpochMillis, state.busy,
                        onRefresh = { viewModel.refreshAllSubscriptionsQuietly() },
                        favoriteKeys = favoriteKeys,
                        onFavorite = { group, outbound -> activeProfile?.id?.let { viewModel.toggleFavoriteServer(it, group, outbound) } },
                        connected = connected,
                        connectionBusy = busy,
                        pingMeasured = offlinePingCompleted,
                        onConnect = {
                            val id = activeProfile?.id
                            if (id == null) viewModel.installManagedSubscription()
                            else if (connected) onVpnStop()
                            else if (block == null && !busy) onVpnStart(id)
                        },
                    )
                    V2Tab.Statistics -> V2Statistics(
                        stats = sessionStats,
                        connected = connected,
                        history = trafficHistory,
                        switchHistory = switchHistory,
                        diagnostics = diagnostics,
                        cumulativeBlocked = state.settings.cumulativeBlocked,
                        showTimeline = policy.features.timeline,
                        onCheckConnection = onMeasurePing,
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
                        uiSettings = state.settings,
                        onLargeText = viewModel::setLargeText,
                        onHighContrast = viewModel::setHighContrast,
                        onReduceMotion = viewModel::setReduceMotion,
                        onHaptics = viewModel::setHapticsEnabled,
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
                        onDnsMode = viewModel::setDnsMode,
                        onNotifyExitIpChange = viewModel::setNotifyExitIpChange,
                        onConnectSound = viewModel::setConnectSoundEnabled,
                        initialNotificationsOpen = settingsNotificationsOpen,
                    )
                    V2Tab.Cards -> V2Cards(
                        onBack = { tab = V2Tab.Home },
                        session = cardSession,
                        requestScope = cardRequestScope,
                    )
                }
                }
            }
            V2BottomBar(tab = tab, onTab = { destination ->
                if (destination == V2Tab.Settings) settingsNotificationsOpen = false
                tab = destination
            })
        }
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
        is UpdateState.UpToDate, is UpdateState.Failure -> true
        else -> false
    }
    val checks = listOf(
        Triple("Сеть", if (networkOnline) "Соединение доступно" else "Проверяем интернет…", networkOnline),
        Triple("Серверы", if (hasServers) "Серверы готовы к выбору" else "Загружаем список серверов…", hasServers),
        Triple("Обновление", if (updateState is UpdateState.Failure) "Недоступно · можно проверить позже" else if (updateReady) "Новая версия не требуется" else "Проверяем обновления…", updateReady),
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
        V2BrandHeader("Добро пожаловать · QuantumVPN 2.0")
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

@Composable
private fun quantum2TextFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedTextColor = Aurora.Text, unfocusedTextColor = Aurora.Text,
    focusedContainerColor = Aurora.Glass.copy(alpha = .78f), unfocusedContainerColor = Aurora.Glass.copy(alpha = .78f),
    focusedPlaceholderColor = Aurora.Muted, unfocusedPlaceholderColor = Aurora.Muted,
    focusedLabelColor = Aurora.Mint, unfocusedLabelColor = Aurora.Muted,
    focusedBorderColor = Aurora.Mint, unfocusedBorderColor = Aurora.Border,
    cursorColor = Aurora.Mint,
)

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
internal fun V2Home(
    policy: ClientPolicy,
    connected: Boolean, busy: Boolean, hasProfile: Boolean, server: String, ping: Int?, adBlock: Boolean, privacyScore: Int, stats: VpnSessionStats,
    onConnect: () -> Unit, onServers: () -> Unit, onSettings: () -> Unit, onCards: () -> Unit,
    reduceMotion: Boolean, onNotifications: () -> Unit,
    pingMeasured: Boolean = false,
    dnsStatus: String = if (connected) "Активен" else "С VPN",
    routingLabel: String = "—",
) {
    val haptic = androidx.compose.ui.platform.LocalHapticFeedback.current
    val hapticsEnabled = LocalAuroraHaptics.current
    val resources = LocalAppResources.current
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
        else -> "Подключиться"
    }
    V2AuroraBackdrop(Modifier.fillMaxSize()) {
        BoxWithConstraints(Modifier.fillMaxSize()) {
        val compact = maxHeight < 620.dp || resources?.compactHome == true
        Column(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 10.dp)
                .padding(bottom = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                AuroraBrandMark(connected = connected, modifier = Modifier.size(34.dp))
                Column(Modifier.weight(1f).padding(start = 8.dp)) {
                    Text(resources?.text("brand_name", policy.branding.name) ?: policy.branding.name, color = Aurora.Text, fontSize = 24.sp, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(
                        resources?.text("tagline", quantum2Tagline(policy.branding.tagline)) ?: quantum2Tagline(policy.branding.tagline),
                        color = Aurora.Muted,
                        fontSize = 12.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                Surface(
                    onClick = onNotifications,
                    shape = CircleShape,
                    color = Color(0xFF152344).copy(alpha = .86f),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Color.White.copy(alpha = .13f)),
                    modifier = Modifier.size(48.dp).semantics { contentDescription = "Открыть настройки и уведомления" },
                ) {
                    Box(contentAlignment = Alignment.Center) { Icon(Icons.Default.Notifications, null, tint = Aurora.Text, modifier = Modifier.size(22.dp)) }
                }
            }
            Spacer(Modifier.height(if (compact) 8.dp else 20.dp))
            AuroraStatusPill(stateText = stateText, stateColor = stateColor, subtitle = stateHint)
            Spacer(Modifier.height(6.dp))
            AuroraConnectButton(
                connected = connected,
                busy = busy,
                enabled = !busy,
                reduceMotion = reduceMotion,
                actionLabel = actionLabel,
                compact = compact,
                onClick = {
                    if (hapticsEnabled) haptic.performHapticFeedback(androidx.compose.ui.hapticfeedback.HapticFeedbackType.LongPress)
                    onConnect()
                },
            )
            Spacer(Modifier.height(if (compact) 8.dp else 20.dp))
            V2GlassPanel(
                modifier = Modifier.fillMaxWidth().clickable(onClick = onServers).testTag("home-server").semantics { contentDescription = "Выбрать сервер" },
            ) {
                Row(Modifier.padding(horizontal = 14.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(serverFlag(server), fontSize = 22.sp)
                    Column(Modifier.weight(1f).padding(start = 10.dp, end = 7.dp)) {
                        Text("Выбранный сервер", color = Color(0xFFB4C7DD), fontSize = 12.sp)
                        Text(server, color = Aurora.Text, fontWeight = FontWeight.SemiBold, fontSize = 15.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    Text("›", color = Color.White.copy(alpha = .72f), fontSize = 22.sp, modifier = Modifier.padding(start = 7.dp))
                }
            }
            Spacer(Modifier.height(8.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                V2HomePill("⌁", "Пинг", serverPingText(ping, pingMeasured), Modifier.weight(1f).testTag("home-ping"), if (ping != null) Aurora.Mint else Aurora.Muted, onServers)
                V2HomePill("●", "DNS", dnsStatus, Modifier.weight(1f).testTag("home-dns"), if (connected) Aurora.Mint else Aurora.Muted, onSettings)
                V2HomePill("≡", "Правила", routingLabel, Modifier.weight(1f).testTag("home-routing"), Aurora.Violet, onSettings)
            }
            Spacer(Modifier.height(8.dp))
            V2GlassPanel(modifier = Modifier.fillMaxWidth().clickable(onClick = onCards).testTag("home-games"), accent = Color(0xFFA88CFF)) {
                Row(Modifier.fillMaxWidth().heightIn(min = 64.dp).padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("♠  ♥", color = Color(0xFFC6A7FF), fontSize = 26.sp)
                    Column(Modifier.weight(1f).padding(start = 12.dp)) {
                        Text(resources?.text("games_title", "Играть с друзьями") ?: "Играть с друзьями", color = Aurora.Text, fontSize = 15.sp, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text("Только виртуальные Q-coins", color = Aurora.Muted, fontSize = 10.sp)
                    }
                    Text("›", color = Aurora.Mint, fontSize = 24.sp)
                }
            }
            if (!hasProfile) {
                Text("Загружаем встроенный список серверов…", color = Color(0xFF5CF5D0), fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
            }
        }
        }
    }
}

/**
 * A deliberately small two-person lobby. The panel stores a PBKDF2 hash of
 * the access code; the APK never receives the panel administrator password.
 */
internal class V2CardSession {
    val displayName = mutableStateOf("")
    val snapshot = mutableStateOf<CardTableSnapshot?>(null)
    val joining = mutableStateOf(false)
    val error = mutableStateOf<String?>(null)
}

@Composable
internal fun V2Cards(
    onBack: () -> Unit,
    session: V2CardSession = remember { V2CardSession() },
    requestScope: kotlinx.coroutines.CoroutineScope = rememberCoroutineScope(),
) {
    val context = LocalContext.current
    val repository = remember(context) { CardTableRepository(context) }
    val scope = requestScope
    // Access codes must not be persisted in the Activity saved-state bundle.
    var accessCode by remember { mutableStateOf("") }
    var displayName by session.displayName
    var snapshot by session.snapshot
    var joining by session.joining
    var error by session.error

    // The server is the source of truth for hands and turns. Polling stops as
    // soon as a match finishes and is cancelled when the screen is left.
    val visible = rememberAuroraVisible()
    BackHandler { onBack() }
    LaunchedEffect(snapshot?.ticket, snapshot?.gamePhase, visible) {
        if (!visible) return@LaunchedEffect
        val ticket = snapshot?.ticket?.takeIf(String::isNotBlank) ?: return@LaunchedEffect
        if (snapshot?.gamePhase == "finished") return@LaunchedEffect
        while (true) {
            repository.state(ticket).onSuccess { refreshed ->
                // Older panel builds omitted ticket from state polling.  Keep
                // the current device-bound ticket as a compatibility guard so
                // the coroutine cannot silently stop after a guest joins.
                val current = snapshot
                if (current == null || refreshed.tableId != current.tableId || refreshed.revision >= current.revision) {
                    snapshot = refreshed.copy(ticket = refreshed.ticket.ifBlank { ticket })
                }
                error = null
            }.onFailure { failure ->
                error = failure.message ?: "Не удалось обновить состояние стола"
            }
            kotlinx.coroutines.delay(if (snapshot?.waiting == true) 5_000 else 2_500)
        }
    }

    V2AuroraBackdrop(Modifier.fillMaxSize()) {
        Column(
            Modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text("Игры", color = Aurora.Text, fontSize = 26.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f).semantics { heading() })
                TextButton(onClick = onBack) { Text("‹ Назад", color = Aurora.Mint) }
            }
            if (snapshot == null) {
                V2GlassPanel(Modifier.fillMaxWidth(), accent = Aurora.Violet) {
                    Row(Modifier.fillMaxWidth().padding(15.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text("♠  ♥  ♣  ♦", color = Color(0xFFC7A6FF), fontSize = 27.sp)
                        Column(Modifier.padding(start = 12.dp).weight(1f)) {
                            Text("Дурак с друзьями", color = Aurora.Text, fontSize = 17.sp, fontWeight = FontWeight.Bold)
                            Text("Только виртуальные Q-coins", color = Aurora.Muted, fontSize = 11.sp)
                        }
                    }
                }
            }
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
                            colors = quantum2TextFieldColors(),
                            modifier = Modifier.fillMaxWidth(),
                        )
                        OutlinedTextField(
                            value = accessCode,
                            onValueChange = { accessCode = it.take(80) },
                            singleLine = true,
                            label = { Text("Код доступа") },
                            colors = quantum2TextFieldColors(),
                            visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Button(
                            onClick = {
                                if (joining) return@Button
                                val enteredCode = accessCode
                                val enteredName = displayName
                                error = null
                                joining = true
                                accessCode = ""
                                scope.launch {
                                    repository.join(enteredCode, enteredName)
                                        .onSuccess { result ->
                                            snapshot = result
                                        }
                                        .onFailure { failure -> error = failure.message ?: "Не удалось войти за стол" }
                                    joining = false
                                }
                            },
                            enabled = !joining && displayName.trim().length >= 2 && accessCode.length >= 8,
                            colors = ButtonDefaults.buttonColors(containerColor = Aurora.Mint, contentColor = Aurora.Night),
                            shape = RoundedCornerShape(15.dp),
                            modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp).testTag("cards-join"),
                        ) {
                            if (joining) CircularProgressIndicator(color = Color.White, strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
                            else Text("Войти по коду и найти игрока", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            } else {
                val table = snapshot!!
                fun play(action: String, card: String = "", target: Int? = null) {
                    if (joining) return
                    joining = true
                    error = null
                    scope.launch {
                        repository.action(table.ticket, action, card, target, table.revision.takeIf { table.hasLegalActions })
                            .onSuccess { result ->
                                if (result.revision >= (snapshot?.revision ?: 0L)) {
                                    snapshot = result.copy(ticket = result.ticket.ifBlank { table.ticket })
                                }
                            }
                            .onFailure { failure ->
                                error = failure.message ?: "Не удалось выполнить ход"
                                repository.state(table.ticket).onSuccess { refreshed ->
                                    if (refreshed.revision >= (snapshot?.revision ?: 0L)) snapshot = refreshed.copy(ticket = refreshed.ticket.ifBlank { table.ticket })
                                }
                            }
                        joining = false
                    }
                }
                V2GlassPanel(modifier = Modifier.fillMaxWidth(), accent = if (table.ready) Aurora.Mint else Color(0xFFC395FF)) {
                    Column(Modifier.padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        if (table.gamePhase != "playing") {
                            Text(if (table.ready) "♠  Стол готов" else "♠  Ожидаем игрока", color = if (table.ready) Aurora.Mint else Color(0xFFCDA4FF), fontSize = 21.sp, fontWeight = FontWeight.Bold)
                            Text("Привет, ${table.name}!", color = Aurora.Text, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                            Text(table.message, color = Aurora.Muted, textAlign = TextAlign.Center, fontSize = 12.sp)
                        }
                        if (table.stakeQCoins > 0 && table.gamePhase != "finished") {
                            Text("Виртуальная ставка: ${table.stakeQCoins} Q-coins с игрока", color = Color(0xFFFFD36E), fontSize = 11.sp)
                        }
                        if (table.opponentName.isNotBlank()) {
                            if (table.gamePhase != "playing") Surface(color = Aurora.Mint.copy(alpha = .12f), shape = RoundedCornerShape(14.dp)) {
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
                                "playing" -> V2DurakTablePreview(table = table, busy = joining,
                                    onAction = { action, card -> play(action, card) },
                                    onDefendTarget = { card, target -> play("defend", card, target) })
                                "finished" -> {
                                    Text(
                                        if (table.winner == "draw") "Ничья. Виртуальная ставка возвращена каждому игроку."
                                        else if (table.winner == table.seat) "Вы выиграли: +${table.winnerRewardQCoins} Q-coins"
                                        else "Партия завершена. Победил ${table.opponentName}. Ставка ${table.stakeQCoins} Q-coins переведена победителю.",
                                        color = if (table.winner == table.seat) Aurora.Mint else Aurora.Muted,
                                        textAlign = TextAlign.Center,
                                        fontWeight = FontWeight.SemiBold,
                                    )
                                    TextButton(onClick = { snapshot = null; error = null }, enabled = !joining) {
                                        Text("Новая партия", color = Aurora.Mint)
                                    }
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
internal fun V2DurakTablePreview(
    table: CardTableSnapshot, busy: Boolean, onAction: (String, String) -> Unit,
    onDefendTarget: (String, Int) -> Unit = { card, _ -> onAction("defend", card) },
) {
    var selectedTarget by remember(table.tableId, table.revision) { mutableStateOf<Int?>(null) }
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
        Text("Дурак с друзьями", color = Aurora.Text, fontWeight = FontWeight.Bold, fontSize = 18.sp)
        Text(if (table.canAttack) "Ваш ход: атакуйте" else if (table.canDefend) "Ваш ход: отбейте карту" else "Ход соперника",
            color = if (table.canAttack || table.canDefend) Aurora.Mint else Aurora.Muted, fontSize = 11.sp, modifier = Modifier.padding(top = 4.dp))
        V2PlayerBadge(table.opponentName, "${table.opponentCards} карт", Modifier.padding(top = 12.dp))
        Box(Modifier.fillMaxWidth().heightIn(min = 196.dp).padding(vertical = 9.dp).testTag("cards-table"), contentAlignment = Alignment.Center) {
            Canvas(Modifier.matchParentSize()) {
                drawOval(Brush.radialGradient(listOf(Color(0xFF155D61), Color(0xFF073437))), topLeft = Offset(0f, 0f), size = size)
                drawOval(Color(0xFF38C3B8).copy(alpha = .55f), topLeft = Offset(1.dp.toPx(), 1.dp.toPx()),
                    size = androidx.compose.ui.geometry.Size(size.width - 2.dp.toPx(), size.height - 2.dp.toPx()), style = Stroke(1.dp.toPx()))
            }
            Column(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Surface(color = Color(0xFF15334A), shape = RoundedCornerShape(8.dp), border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF93B6CB)),
                            modifier = Modifier.size(40.dp, 55.dp)) { Box(contentAlignment = Alignment.Center) { Text("Q", color = Aurora.Mint, fontSize = 23.sp, fontWeight = FontWeight.Bold) } }
                        Text("Колода ${table.deckCount}", color = Color(0xFFB6D8D6), fontSize = 9.sp, modifier = Modifier.padding(top = 4.dp))
                        Text("♠ Отбой ${table.discardCount}", color = Aurora.Muted, fontSize = 10.sp,
                            modifier = Modifier.padding(top = 5.dp).testTag("cards-discard"))
                    }
                    if (table.trump.isNotBlank()) Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        V2DurakCard(table.trump, false) {}
                        Text("Козырь", color = Color(0xFFB6D8D6), fontSize = 9.sp, modifier = Modifier.padding(top = 3.dp))
                    }
                }
                if (table.tableCards.isEmpty()) Text("Стол свободен", color = Color(0xFFB6D8D6), fontSize = 12.sp, modifier = Modifier.padding(vertical = 12.dp))
                else Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(top = 10.dp), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                    table.tableCards.forEachIndexed { index, pair ->
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            V2DurakCard(pair.attack, !busy && table.canDefend && pair.defense.isBlank()) { selectedTarget = index }
                            if (selectedTarget == index) Text("Отбить эту", color = Aurora.Mint, fontSize = 9.sp)
                            if (pair.defense.isNotBlank()) V2DurakCard(pair.defense, false) {}
                        }
                    }
                }
            }
        }
        V2PlayerBadge(table.name, "Вы · ${table.hand.size} карт")
        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            table.hand.forEach { card ->
                val defense = table.legalDefenses.firstOrNull { it.card == card && (selectedTarget == null || it.target == selectedTarget) }
                val legal = if (!table.hasLegalActions) table.canAttack || table.canDefend
                    else (table.canAttack && card in table.legalAttackCards) || (table.canDefend && defense != null)
                V2DurakCard(card, !busy && legal) {
                    if (table.canAttack) onAction("attack", card)
                    else if (defense != null) onDefendTarget(card, defense.target)
                    else onAction("defend", card)
                }
            }
        }
        Row(Modifier.fillMaxWidth().padding(top = 10.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { onAction("take", "") }, enabled = !busy && table.canTake, shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Aurora.Mint, contentColor = Aurora.Night),
                modifier = Modifier.weight(1f).heightIn(min = 48.dp)) { Text("Беру", fontWeight = FontWeight.Bold) }
            Button(onClick = { onAction("pass", "") }, enabled = !busy && table.canPass, shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Aurora.Violet, contentColor = Color.White),
                modifier = Modifier.weight(1f).heightIn(min = 48.dp).testTag("cards-pass")) { Text("Отбой", fontWeight = FontWeight.Bold) }
        }
        Text(if (table.canTake && table.hasLegalActions && table.legalDefenses.isEmpty()) "Нет карты для защиты — нажмите «Беру»."
            else "Нажмите доступную карту. Для защиты можно сначала выбрать атаку на столе.", color = Aurora.Muted, textAlign = TextAlign.Center, fontSize = 10.sp, modifier = Modifier.padding(top = 8.dp))
    }
}

@Composable
private fun V2PlayerBadge(name: String, detail: String, modifier: Modifier = Modifier) {
    Column(modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Surface(color = Aurora.Violet.copy(alpha = .22f), shape = CircleShape, border = androidx.compose.foundation.BorderStroke(2.dp, Aurora.Mint),
            modifier = Modifier.size(43.dp)) {
            Box(contentAlignment = Alignment.Center) { Text(name.take(1).uppercase().ifBlank { "?" }, color = Aurora.Text, fontSize = 22.sp, fontWeight = FontWeight.Bold) }
        }
        Text(name, color = Aurora.Text, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
        Text(detail, color = Aurora.Muted, fontSize = 10.sp)
    }
}

@Composable
private fun V2DurakCard(card: String, enabled: Boolean, onClick: () -> Unit) {
    val label = durakCardLabel(card)
    val rank = card.dropLast(1).ifBlank { "?" }
    val suit = label.takeLast(1)
    val red = suit == "♥" || suit == "♦"
    val ink = if (red) Color(0xFFC7385C) else Color(0xFF13212F)
    Surface(onClick = onClick, enabled = enabled, color = Color(0xFFF4F8FC), shape = RoundedCornerShape(8.dp),
        border = androidx.compose.foundation.BorderStroke(if (enabled) 2.dp else 1.dp, if (enabled) Aurora.Mint else Color(0xFFB8CDDD)),
        modifier = Modifier.size(width = 54.dp, height = 77.dp).semantics { contentDescription = "Карта $label" }) {
        Box(Modifier.padding(5.dp)) {
            Text(rank, color = ink, fontWeight = FontWeight.Bold, fontSize = 13.sp, modifier = Modifier.align(Alignment.TopStart))
            Text(suit, color = ink, fontWeight = FontWeight.Bold, fontSize = 27.sp, modifier = Modifier.align(Alignment.Center))
            Text(rank, color = ink, fontWeight = FontWeight.Bold, fontSize = 11.sp, modifier = Modifier.align(Alignment.BottomEnd))
        }
    }
}

private fun durakCardLabel(card: String): String {
    if (card.length < 2) return "?"
    val suit = when (card.last()) { 'S' -> '♠'; 'H' -> '♥'; 'D' -> '♦'; 'C' -> '♣'; else -> '?' }
    return card.dropLast(1) + " " + suit
}

@Composable
private fun V2HomePill(icon: String, title: String, value: String, modifier: Modifier, accent: Color, onClick: () -> Unit) {
    V2GlassPanel(modifier = modifier.clickable(onClick = onClick), accent = accent) {
        Row(Modifier.heightIn(min = 54.dp).padding(horizontal = 8.dp, vertical = 9.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(icon, color = accent, fontSize = 18.sp)
            Column(Modifier.padding(start = 6.dp).weight(1f)) {
                Text(title, color = Aurora.Muted, fontSize = 10.sp)
                Text(value, color = Aurora.Text, fontWeight = FontWeight.SemiBold, fontSize = 11.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

@Composable
internal fun V2Servers(
    groups: List<RuntimeSelectorGroup>, groupTag: String?, selected: String?,
    offlinePings: Map<String, Int>, onSelect: (String, String) -> Unit, profileId: String?,
    reliabilityScores: Map<String, Int>, updatedAt: Long?, busy: Boolean, onRefresh: () -> Unit,
    favoriteKeys: Set<String> = emptySet(), onFavorite: (String, String) -> Unit = { _, _ -> },
    connected: Boolean = false, connectionBusy: Boolean = false,
    pingMeasured: Boolean = false, onConnect: () -> Unit = {},
) {
    var allServersOpen by rememberSaveable { mutableStateOf(false) }
    var search by rememberSaveable { mutableStateOf("") }
    var protocol by rememberSaveable { mutableStateOf("") }
    var category by rememberSaveable { mutableStateOf("Все") }
    val entries = groups.flatMap { group -> group.items.map { group to it } }
        .distinctBy { (group, item) -> group.tag to item.tag }
    fun favorite(group: RuntimeSelectorGroup, server: com.quantumvpn.vpn.RuntimeOutboundItem): Boolean =
        profileId != null && FavoriteServersStore.key(profileId, group.tag, server.tag) in favoriteKeys
    fun reliability(group: RuntimeSelectorGroup, server: com.quantumvpn.vpn.RuntimeOutboundItem): Int {
        val key = profileId?.let { DeadServerQuarantineStore.serverKey(it, group.tag, server.tag) }
        return key?.let(reliabilityScores::get) ?: reliabilityScores[server.tag] ?: 50
    }
    fun chosen(group: RuntimeSelectorGroup, server: com.quantumvpn.vpn.RuntimeOutboundItem) =
        server.tag == if (group.tag == groupTag) selected else group.selected
    val filtered = entries.filter { (group, item) ->
        (protocol.isBlank() || item.type == protocol) &&
            (search.isBlank() || item.tag.contains(search, true) || group.tag.contains(search, true)) &&
            when (category) {
                "Избранные" -> favorite(group, item)
                "Резерв" -> item.tag.contains("резерв", true) || item.tag.contains("reserve", true) || item.tag.contains("backup", true)
                else -> true
            }
    }.sortedWith(compareByDescending<Pair<RuntimeSelectorGroup, com.quantumvpn.vpn.RuntimeOutboundItem>> { (group, item) -> chosen(group, item) }
        .thenBy { (_, item) -> item.pingMillis ?: offlinePings[item.tag] ?: Int.MAX_VALUE }
        .thenByDescending { (group, item) -> reliability(group, item) })
    val updated = updatedAt?.let { java.text.SimpleDateFormat("dd.MM HH:mm", java.util.Locale.getDefault()).format(java.util.Date(it)) }
    @Composable
    fun ServerRow(group: RuntimeSelectorGroup, item: com.quantumvpn.vpn.RuntimeOutboundItem) {
        val ping = if (connected) item.pingMillis ?: offlinePings[item.tag] else offlinePings[item.tag]
        val selectedServer = chosen(group, item)
        val isFavorite = favorite(group, item)
        Surface(
            onClick = { if (group.selectable) onSelect(group.tag, item.tag) },
            enabled = group.selectable,
            color = if (selectedServer) Aurora.Mint.copy(alpha = .12f) else Aurora.Glass.copy(alpha = .84f),
            border = androidx.compose.foundation.BorderStroke(1.dp, if (selectedServer) Aurora.Mint else Aurora.Border),
            shape = RoundedCornerShape(15.dp),
            modifier = Modifier.fillMaxWidth().padding(bottom = 6.dp).semantics { contentDescription = "Сервер ${item.tag}${if (selectedServer) ", выбран" else ""}" },
        ) {
            Row(Modifier.padding(start = 10.dp, end = 8.dp, top = 5.dp, bottom = 5.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(serverFlag(item.tag), fontSize = 22.sp)
                Column(Modifier.weight(1f).padding(start = 9.dp, end = 4.dp)) {
                    Text(item.tag, color = Aurora.Text, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(item.type.uppercase() + if (groups.size > 1) " · ${group.tag}" else "", color = Aurora.Muted, fontSize = 9.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                TextButton(
                    onClick = { onFavorite(group.tag, item.tag) }, enabled = profileId != null,
                    contentPadding = PaddingValues(0.dp),
                    modifier = Modifier.size(48.dp).semantics { contentDescription = if (isFavorite) "Убрать ${item.tag} из избранного" else "Добавить ${item.tag} в избранное" },
                ) { Text(if (isFavorite) "★" else "☆", color = if (isFavorite) Color(0xFFFFD36E) else Aurora.Muted, fontSize = 22.sp) }
                Surface(
                    color = if (ping != null) Aurora.Mint.copy(alpha = .12f) else Aurora.Border.copy(alpha = .22f),
                    shape = RoundedCornerShape(99.dp),
                ) {
                    Text(serverPingText(ping, pingMeasured), color = if (ping != null) Aurora.Mint else Aurora.Muted, fontWeight = FontWeight.Bold,
                        fontSize = 10.sp, modifier = Modifier.padding(horizontal = 8.dp, vertical = 5.dp))
                }
                Text(if (selectedServer) "✓" else "›", color = if (selectedServer) Aurora.Mint else Aurora.Muted, fontSize = 18.sp, modifier = Modifier.padding(start = 7.dp))
            }
        }
    }
    if (allServersOpen) {
        AlertDialog(
            onDismissRequest = { allServersOpen = false },
            title = { Text("Серверы · ${filtered.size}") },
            text = {
                LazyColumn(Modifier.heightIn(max = 420.dp)) {
                    items(filtered, key = { (group, item) -> "${group.tag}|${item.tag}" }) { (group, item) -> ServerRow(group, item) }
                }
            },
            confirmButton = { TextButton(onClick = { allServersOpen = false }) { Text("Готово") } },
        )
    }
    V2AuroraBackdrop(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize().padding(horizontal = 16.dp, vertical = 10.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text("Серверы", color = Aurora.Text, fontSize = 26.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f).semantics { heading() })
                TextButton(onClick = onRefresh, enabled = !busy) { Text(if (busy) "…" else "Обновить", color = Aurora.Mint, fontSize = 11.sp) }
            }
            OutlinedTextField(search, { search = it.take(80) }, placeholder = { Text("Поиск страны или сервера…", fontSize = 12.sp) },
                colors = quantum2TextFieldColors(),
                singleLine = true, shape = RoundedCornerShape(15.dp), modifier = Modifier.fillMaxWidth().testTag("server-search"))
            Row(Modifier.fillMaxWidth().padding(top = 7.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf("Все", "Избранные", "Резерв").forEach { label ->
                    Surface(onClick = { category = label }, shape = RoundedCornerShape(99.dp),
                        color = if (category == label) Aurora.Mint else Aurora.Glass,
                        border = androidx.compose.foundation.BorderStroke(1.dp, if (category == label) Aurora.Mint else Aurora.Border),
                        modifier = Modifier.weight(1f).heightIn(min = 48.dp)) {
                        Box(contentAlignment = Alignment.Center) { Text(label, color = if (category == label) Aurora.Night else Aurora.Muted, fontSize = 11.sp, fontWeight = FontWeight.SemiBold) }
                    }
                }
            }
            Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(top = 2.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                (listOf("") + entries.map { it.second.type }.distinct()).forEach { kind ->
                    androidx.compose.material3.FilterChip(selected = protocol == kind, onClick = { protocol = kind },
                        colors = androidx.compose.material3.FilterChipDefaults.filterChipColors(
                            containerColor = Aurora.Glass, labelColor = Aurora.Muted,
                            selectedContainerColor = Aurora.Mint, selectedLabelColor = Aurora.Night),
                        label = { Text(if (kind.isBlank()) "Все протоколы" else kind.uppercase(), fontSize = 10.sp) })
                }
            }
            if (filtered.isEmpty()) {
                V2GlassPanel(Modifier.fillMaxWidth().padding(vertical = 12.dp), accent = Aurora.Violet) {
                    Text(if (category == "Избранные") "Добавьте сервер в избранное кнопкой ☆" else if (entries.isEmpty()) "Нет серверов. Обновите подписку и проверьте сеть." else "По вашему фильтру серверов нет.",
                        color = Aurora.Muted, fontSize = 12.sp, modifier = Modifier.padding(14.dp))
                }
            } else {
                Column(Modifier.weight(1f, fill = false).verticalScroll(rememberScrollState()).padding(top = 3.dp)) {
                    filtered.take(5).forEach { (group, item) -> ServerRow(group, item) }
                    if (filtered.size > 5) TextButton(onClick = { allServersOpen = true }, modifier = Modifier.fillMaxWidth()) {
                        Text("Все серверы (${filtered.size})", color = Aurora.Mint, fontSize = 11.sp)
                    }
                }
            }
            Spacer(Modifier.height(2.dp))
            Text(if (updated == null) "Пинг измеряется и без VPN · каждые 20 секунд" else "Обновлено $updated · пинг каждые 20 секунд",
                color = Aurora.Muted, fontSize = 9.sp, modifier = Modifier.padding(vertical = 6.dp))
            Button(onClick = onConnect, enabled = !connectionBusy, shape = RoundedCornerShape(15.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Aurora.Mint, contentColor = Aurora.Night),
                modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp).testTag("servers-connect")) {
                Text(if (connectionBusy) "Подключение…" else if (connected) "Отключить" else "Подключиться", fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
internal fun V2Statistics(
    stats: VpnSessionStats,
    connected: Boolean,
    history: List<SessionTrafficRecord>,
    switchHistory: List<ServerSwitchEvent>,
    diagnostics: DiagnosticState,
    cumulativeBlocked: Long,
    showTimeline: Boolean,
    onCheckConnection: () -> Unit = {},
) {
    var period by rememberSaveable { mutableStateOf("Сегодня") }
    var historyOpen by rememberSaveable { mutableStateOf(false) }
    var now by remember { mutableStateOf(System.currentTimeMillis()) }
    val visible = rememberAuroraVisible()
    LaunchedEffect(connected, visible) {
        while (connected && visible) { now = System.currentTimeMillis(); kotlinx.coroutines.delay(1_000) }
    }
    val seconds = stats.connectedAtEpochMillis?.let { ((now - it) / 1_000).coerceAtLeast(0) } ?: 0
    val startOfDay = java.util.Calendar.getInstance().apply {
        timeInMillis = now; set(java.util.Calendar.HOUR_OF_DAY, 0); set(java.util.Calendar.MINUTE, 0)
        set(java.util.Calendar.SECOND, 0); set(java.util.Calendar.MILLISECOND, 0)
        if (period == "Неделя") add(java.util.Calendar.DAY_OF_YEAR, -6)
    }.timeInMillis
    val records = history.filter { it.epochMillis >= startOfDay }
    val download = records.sumOf { it.downloadBytes } + stats.downloadTotalBytes
    val upload = records.sumOf { it.uploadBytes } + stats.uploadTotalBytes
    val networkHealthy = diagnostics.network?.validated == true
    if (historyOpen) {
        AlertDialog(onDismissRequest = { historyOpen = false }, title = { Text("История · $period") }, text = {
            LazyColumn(Modifier.heightIn(max = 380.dp)) {
                if (records.isEmpty()) item { Text("За этот период завершённых сессий нет.") }
                items(records) { entry ->
                    Column(Modifier.padding(vertical = 8.dp)) {
                        Text(entry.profileName, fontWeight = FontWeight.SemiBold)
                        Text(java.text.SimpleDateFormat("dd.MM HH:mm", java.util.Locale.getDefault()).format(java.util.Date(entry.epochMillis)) +
                            " · ↓ " + formatBytes(entry.downloadBytes) + " · ↑ " + formatBytes(entry.uploadBytes), fontSize = 11.sp)
                    }
                }
            }
        }, confirmButton = { TextButton(onClick = { historyOpen = false }) { Text("Готово") } })
    }
    V2AuroraBackdrop(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 10.dp)) {
            Text("Статистика", color = Aurora.Text, fontSize = 26.sp, fontWeight = FontWeight.Bold, modifier = Modifier.semantics { heading() })
            Row(Modifier.fillMaxWidth().padding(top = 10.dp, bottom = 8.dp), horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                listOf("Сегодня", "Неделя").forEach { label ->
                    Surface(onClick = { period = label }, shape = RoundedCornerShape(12.dp),
                        color = if (period == label) Aurora.Mint else Aurora.Glass,
                        border = androidx.compose.foundation.BorderStroke(1.dp, if (period == label) Aurora.Mint else Aurora.Border),
                        modifier = Modifier.weight(1f).heightIn(min = 48.dp)) {
                        Box(contentAlignment = Alignment.Center) { Text(label, color = if (period == label) Aurora.Night else Aurora.Text, fontSize = 12.sp, fontWeight = FontWeight.SemiBold) }
                    }
                }
            }
            TrafficChart(stats, compact = true)
            Text("График текущей сессии · измеренная скорость", color = Aurora.Muted, fontSize = 10.sp, modifier = Modifier.padding(bottom = 8.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                V2Metric("↓ Загрузка · $period", formatBytes(download), Modifier.weight(1f))
                V2Metric("↑ Отдача · $period", formatBytes(upload), Modifier.weight(1f))
            }
            Spacer(Modifier.height(8.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                V2Metric("⌁ Пинг", stats.pingMillis?.let { "$it мс" } ?: "—", Modifier.weight(1f))
                V2Metric("◷ Сессия", "${seconds / 60} мин", Modifier.weight(1f))
            }
            Spacer(Modifier.height(8.dp))
            V2GlassPanel(Modifier.fillMaxWidth()) {
                Row(Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 10.dp)) {
                    V2StatisticLine("Потери", stats.pingLossPercent?.let { "$it%" } ?: "—", modifier = Modifier.weight(1f))
                    V2StatisticLine("Сеть", if (networkHealthy) "Проверена" else if (diagnostics.network == null) "Нет данных" else "Нет проверки", modifier = Modifier.weight(1f))
                    V2StatisticLine("Блокировки", "$cumulativeBlocked", Aurora.Mint, Modifier.weight(1f))
                }
            }
            Button(onClick = onCheckConnection, enabled = connected,
                colors = ButtonDefaults.buttonColors(containerColor = Aurora.Mint.copy(alpha = .10f), contentColor = Aurora.Mint,
                    disabledContainerColor = Aurora.Glass.copy(alpha = .86f), disabledContentColor = Aurora.Muted),
                border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Mint),
                shape = RoundedCornerShape(15.dp), modifier = Modifier.fillMaxWidth().padding(top = 9.dp).heightIn(min = 50.dp).testTag("statistics-check")) {
                Text(if (connected) "⌁  Проверить связь" else "Подключите VPN для проверки", fontWeight = FontWeight.SemiBold)
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                TextButton(onClick = { historyOpen = true }) { Text("История сессий", color = Aurora.Muted, fontSize = 11.sp) }
                if (showTimeline) Text("Смен сервера: ${switchHistory.size}", color = Aurora.Muted, fontSize = 10.sp, modifier = Modifier.padding(top = 16.dp))
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
internal fun V2Settings(
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
    uiSettings: UiSettings,
    onLargeText: (Boolean) -> Unit,
    onHighContrast: (Boolean) -> Unit,
    onReduceMotion: (Boolean) -> Unit,
    onHaptics: (Boolean) -> Unit,
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
    onDnsMode: (com.quantumvpn.config.DnsMode) -> Unit = {},
    onNotifyExitIpChange: (Boolean) -> Unit = {},
    onConnectSound: (Boolean) -> Unit = {},
    initialNotificationsOpen: Boolean = false,
    communityNetworkEnabled: Boolean = true,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var logStatus by remember { mutableStateOf("") }
    val communityRepository = remember(context) { CommunityRepository(context) }
    var qualityConsent by remember { mutableStateOf(communityRepository.qualityConsent()) }
    var supportOpen by rememberSaveable { mutableStateOf(false) }
    var logConsentOpen by rememberSaveable { mutableStateOf(false) }
    var privacyOpen by rememberSaveable { mutableStateOf(false) }
    var notificationsOpen by rememberSaveable(initialNotificationsOpen) { mutableStateOf(initialNotificationsOpen) }
    var aboutOpen by rememberSaveable { mutableStateOf(false) }
    var donateOpen by rememberSaveable { mutableStateOf(false) }
    var appearanceOpen by rememberSaveable { mutableStateOf(false) }
    var accessibilityOpen by rememberSaveable { mutableStateOf(false) }
    var resourcesOpen by rememberSaveable { mutableStateOf(false) }
    var selectedGroup by rememberSaveable { mutableStateOf<String?>(null) }
    if (resourcesOpen) {
        ResourceStatusDialog((LocalContext.current.applicationContext as QuantumVpnApplication).container.appResourceRepository) { resourcesOpen = false }
    }
    if (accessibilityOpen) {
        V2AccessibilityPage(uiSettings, onLargeText, onHighContrast, onReduceMotion, onHaptics) { accessibilityOpen = false }
        return
    }
    BackHandler(appearanceOpen || privacyOpen || notificationsOpen || supportOpen || aboutOpen || donateOpen || selectedGroup != null) {
        if (!(appearanceOpen || privacyOpen || notificationsOpen || supportOpen || aboutOpen || donateOpen)) selectedGroup = null
        appearanceOpen = false; privacyOpen = false; notificationsOpen = false
        supportOpen = false
        aboutOpen = false; donateOpen = false
    }
    if (appearanceOpen) {
        V2AppearancePage(
            style = backgroundStyle,
            customBackgroundUri = customBackgroundUri,
            touchBubblesEnabled = touchBubblesEnabled,
            onStyle = onBackgroundStyle,
            onCustomBackgroundUri = onCustomBackgroundUri,
            onTouchBubbles = onTouchBubbles,
            onBack = { appearanceOpen = false },
            reduceMotion = uiSettings.reduceMotion,
            onReduceMotion = onReduceMotion,
            theme = theme,
            onTheme = onTheme,
            dynamicColor = dynamicColor,
            onDynamicColor = onDynamicColor,
            onAccessibility = { accessibilityOpen = true },
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
        NotificationInboxScreen(
            onBack = { notificationsOpen = false },
            onOpenSupport = { notificationsOpen = false; supportOpen = true },
            networkEnabled = communityNetworkEnabled,
        )
        return
    }
    if (supportOpen) {
        SupportCenterScreen(
            onBack = { supportOpen = false },
            onOpenInbox = { supportOpen = false; notificationsOpen = true },
            networkEnabled = communityNetworkEnabled,
            diagnosticProvider = {
                JSONObject().put("app_version", BuildConfig.VERSION_NAME)
                    .put("android_version", android.os.Build.VERSION.RELEASE)
                    .put("last_error", DiagnosticReportRedactor.redact(diagnostics.lastFailure?.message.orEmpty()).take(600))
                    .put("logs", DiagnosticReportRedactor.redact(diagnostics.logs.takeLast(20).joinToString("\n") { it.message }).take(3000))
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
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(9.dp)) {
            if (selectedGroup != null) {
                TextButton(onClick = { selectedGroup = null }) { Text("← Настройки", color = Aurora.Mint) }
                Text(selectedGroup!!, color = Aurora.Text, fontSize = 26.sp, fontWeight = FontWeight.Bold, modifier = Modifier.semantics { heading() })
            } else {
                Text("Настройки", color = Aurora.Text, fontSize = 26.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(bottom = 7.dp).semantics { heading() })
            }
            when (selectedGroup) {
                "Подключение" -> {
                    V2Toggle("DNS и блокировка рекламы", "Работают в VPN; системный Private DNS Android не изменяется", adBlock, onAdBlock)
                    V2Toggle("Аварийная защита", "Блокировать трафик вне VPN — может ограничить доступ к сети", killSwitch, onKillSwitch)
                    V2Toggle("Автоподключение", "Подключаться при переходе на мобильную сеть", autoConnect, onAutoConnect)
                    V2Toggle("Неизвестный Wi-Fi", "Защита при подключении к незнакомой сети", protectUnknownWifi, onProtectUnknownWifi)
                    V2Toggle("Режим поездки", "Готовность к смене сети и восстановлению соединения", travelMode, onTravelMode)
                    V2SettingsGroup("DNS-сервер") {
                        com.quantumvpn.config.DnsMode.entries.forEach { mode ->
                            V2CompactToggle(when (mode) {
                                com.quantumvpn.config.DnsMode.Automatic -> "Автоматически"
                                com.quantumvpn.config.DnsMode.Android -> "DNS сети Android"
                                com.quantumvpn.config.DnsMode.Secure -> "Защищённый DNS"
                                com.quantumvpn.config.DnsMode.FromJson -> "Из конфигурации"
                            }, uiSettings.dnsMode == mode) { checked -> if (checked) onDnsMode(mode) }
                        }
                    }
                    V2NavRow("Конфиденциальность", "Проверка защиты и обработки данных") { privacyOpen = true }
                }
                "Уведомления" -> {
                    V2Toggle("Уведомления приложения", "Состояние соединения, обновления и события сервиса", notifications, onNotifications)
                    V2Toggle("Изменение выходного IP", "Уведомлять при смене адреса VPN", uiSettings.notifyExitIpChange, onNotifyExitIpChange)
                    V2Toggle("Звук подключения", "Короткий сигнал при установлении соединения", uiSettings.connectSoundEnabled, onConnectSound)
                    V2NavRow("Центр уведомлений", "История обновлений и технических работ") { notificationsOpen = true }
                    V2NavRow("Разрешение Android", "Открыть системные настройки уведомлений") {
                        runCatching { context.startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply { putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName) }) }
                    }
                }
                "Помощь" -> {
                    V2NavRow("Написать в поддержку", "Переписка с оператором и ответ в уведомлениях") { supportOpen = true }
                    V2Toggle("Делиться качеством подключения", "Добровольно: время подключения, ping и ошибки. Без истории сайтов, IP и ключей.", qualityConsent) { consent ->
                        qualityConsent = consent
                        communityRepository.setQualityConsent(consent)
                    }
                    V2NavRow("Проверить обновление", "Установка проверенного APK через системный Android") { onCheckUpdate() }
                    V2NavRow("Ресурсы и исправления", "Подписанные правила и ресурсы из Quantum Control") { resourcesOpen = true }
                    V2NavRow("Отправить диагностику", "Только после вашего согласия, без паролей и ключей") { logConsentOpen = true }
                    V2NavRow("Конфиденциальность", "Защита данных и состояние настроек") { privacyOpen = true }
                    V2NavRow("Поддержать проект", "ЮMoney во внешнем браузере") { donateOpen = true }
                    V2NavRow("О приложении", "Версия и список изменений") { aboutOpen = true }
                    if (logStatus.isNotBlank()) Text(logStatus, color = Aurora.Muted, fontSize = 11.sp)
                }
                else -> {
                    V2SettingsHubRow("⌁", "Подключение", "Протоколы, автоподключение, защита сети", "settings-connection") { selectedGroup = "Подключение" }
                    V2SettingsHubRow("♧", "Уведомления", "Статус соединения, звуки, важные события", "settings-notifications") { selectedGroup = "Уведомления" }
                    V2SettingsHubRow("◉", "Оформление", "Темы, фон, анимации и доступность", "settings-appearance") { appearanceOpen = true }
                    V2SettingsHubRow("?", "Помощь", "Обновление, диагностика, о приложении", "settings-help") { selectedGroup = "Помощь" }
                    Spacer(Modifier.height(13.dp))
                    Row(Modifier.align(Alignment.CenterHorizontally), verticalAlignment = Alignment.CenterVertically) {
                        AuroraBrandMark(connected = vpnConnected, modifier = Modifier.size(30.dp))
                        Text("QuantumVPN 2.0", color = Aurora.Text, fontSize = 13.sp, modifier = Modifier.padding(start = 7.dp))
                    }
                    Text("Стабильность. Свобода. Ближе к вам.", color = Aurora.Muted, fontSize = 11.sp, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
                }
            }
        }
    }
}

@Composable
private fun V2SettingsHubRow(icon: String, title: String, subtitle: String, tag: String, onClick: () -> Unit) {
    Surface(onClick = onClick, color = Aurora.Glass.copy(alpha = .88f), shape = RoundedCornerShape(18.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border),
        modifier = Modifier.fillMaxWidth().heightIn(min = 76.dp).testTag(tag)) {
        Row(Modifier.padding(horizontal = 15.dp, vertical = 14.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(icon, color = Aurora.Mint, fontSize = 29.sp, modifier = Modifier.width(38.dp))
            Column(Modifier.weight(1f).padding(start = 7.dp, end = 6.dp)) {
                Text(title, color = Aurora.Text, fontSize = 15.sp, fontWeight = FontWeight.Bold)
                Text(subtitle, color = Aurora.Muted, fontSize = 11.sp, modifier = Modifier.padding(top = 3.dp))
            }
            Text("›", color = Aurora.Muted, fontSize = 26.sp)
        }
    }
}

@Composable
internal fun V2AppearancePage(
    style: AppBackgroundStyle,
    customBackgroundUri: String,
    touchBubblesEnabled: Boolean,
    onStyle: (AppBackgroundStyle) -> Unit,
    onCustomBackgroundUri: (String) -> Unit,
    onTouchBubbles: (Boolean) -> Unit,
    onBack: () -> Unit,
    reduceMotion: Boolean = false,
    onReduceMotion: (Boolean) -> Unit = {},
    theme: ThemeMode = ThemeMode.Dark,
    onTheme: (ThemeMode) -> Unit = {},
    dynamicColor: Boolean = false,
    onDynamicColor: (Boolean) -> Unit = {},
    onAccessibility: () -> Unit = {},
) {
    val context = LocalContext.current
    var previewId by remember { mutableStateOf<Long?>(null) }
    BackHandler { onBack() }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            runCatching { context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
            onCustomBackgroundUri(uri.toString())
            onStyle(AppBackgroundStyle.Custom)
        }
    }
    LaunchedEffect(previewId) { if (previewId != null) { kotlinx.coroutines.delay(550); previewId = null } }
    val customBitmap by produceState<android.graphics.Bitmap?>(null, customBackgroundUri) {
        value = if (customBackgroundUri.isBlank()) null else withContext(Dispatchers.IO) {
            runCatching { decodeCustomBackground(context, Uri.parse(customBackgroundUri)) }.getOrNull()
        }
    }
    V2AuroraBackdrop(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(9.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = onBack, contentPadding = PaddingValues(0.dp)) { Text("‹", color = Aurora.Mint, fontSize = 30.sp) }
                Text("Оформление", color = Aurora.Text, fontSize = 26.sp, fontWeight = FontWeight.Bold, modifier = Modifier.semantics { heading() })
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                listOf(AppBackgroundStyle.Aurora, AppBackgroundStyle.NightCity, AppBackgroundStyle.Custom).forEach { background ->
                    val selected = background == style
                    Column(Modifier.weight(1f), horizontalAlignment = Alignment.CenterHorizontally) {
                        Surface(onClick = {
                            if (background == AppBackgroundStyle.Custom && customBackgroundUri.isBlank()) picker.launch(arrayOf("image/*"))
                            else onStyle(background)
                        }, color = Aurora.Glass, shape = RoundedCornerShape(15.dp),
                            border = androidx.compose.foundation.BorderStroke(if (selected) 2.dp else 1.dp, if (selected) Aurora.Mint else Aurora.Border),
                            modifier = Modifier.fillMaxWidth().height(112.dp).testTag(when (background) {
                                AppBackgroundStyle.Aurora -> "background-aurora"
                                AppBackgroundStyle.NightCity -> "background-city"
                                else -> "background-custom"
                            })) {
                            Box(Modifier.fillMaxSize()) {
                                when (background) {
                                    AppBackgroundStyle.Aurora -> AuroraGlassBackdrop(Modifier.fillMaxSize(), motionEnabled = false)
                                    AppBackgroundStyle.Custom -> if (customBitmap != null) {
                                        Image(customBitmap!!.asImageBitmap(), null, contentScale = ContentScale.Crop, modifier = Modifier.fillMaxSize())
                                    } else Box(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Color(0xFF725389), Color(0xFF151E39)))),
                                        contentAlignment = Alignment.Center) { Text("▧", color = Aurora.Muted, fontSize = 34.sp) }
                                    else -> Canvas(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Color(0xFF242B52), Color(0xFF753559), Color(0xFF061326))))) {
                                        (0..7).forEach { index ->
                                            val left = size.width * index / 8
                                            val height = size.height * (.23f + (index % 4) * .13f)
                                            drawRect(Color(0xFF0C142D), Offset(left, size.height - height), androidx.compose.ui.geometry.Size(size.width / 9, height))
                                            (1..4).forEach { floor -> drawLine(Color(0xFFE1A366).copy(alpha = .8f), Offset(left + 3f, size.height - floor * height / 5), Offset(left + size.width / 11, size.height - floor * height / 5), 2f) }
                                        }
                                    }
                                }
                                if (selected) Text("✓", color = Aurora.Night, fontWeight = FontWeight.Bold, modifier = Modifier.align(Alignment.TopEnd).padding(7.dp).background(Aurora.Mint, CircleShape).padding(horizontal = 5.dp, vertical = 1.dp))
                            }
                        }
                        Text(when (background) { AppBackgroundStyle.Aurora -> "Сияние"; AppBackgroundStyle.NightCity -> "Город"; else -> "Мой фон" },
                            color = Aurora.Text, fontSize = 11.sp, modifier = Modifier.padding(top = 4.dp))
                    }
                }
            }
            Button(onClick = { picker.launch(arrayOf("image/*")) }, shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent, contentColor = Aurora.Mint),
                border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Mint),
                modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp).testTag("background-upload")) {
                Text("▧  Загрузить свой фон", fontWeight = FontWeight.Bold)
            }
            Box(Modifier.testTag("appearance-animations")) { V2Toggle("Анимации", "Плавные переходы и эффекты", !reduceMotion) { onReduceMotion(!it) } }
            Box(Modifier.testTag("appearance-touch-effects")) { V2Toggle("Эффекты касания", "Визуальный отклик при нажатии", touchBubblesEnabled, onTouchBubbles) }
            Box(Modifier.fillMaxWidth().height(56.dp)) {
                Button(onClick = { if (touchBubblesEnabled && !reduceMotion) previewId = System.nanoTime() },
                    shape = RoundedCornerShape(16.dp), border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Violet),
                    colors = ButtonDefaults.buttonColors(containerColor = Aurora.Violet.copy(alpha = .16f), contentColor = Aurora.Text),
                    modifier = Modifier.fillMaxSize().testTag("appearance-preview")) { Text(if (previewId != null) "✓  Плавный отклик" else "◎  Попробовать") }
                val density = LocalDensity.current
                previewId?.let { id -> V2TouchWave(AuroraTapBubble(id, Offset(with(density) { 180.dp.toPx() }, with(density) { 28.dp.toPx() })), Aurora.Mint) }
            }
            V2SettingsGroup("Тема") {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                    ThemeMode.entries.forEach { mode ->
                        V2MiniNav(when (mode) { ThemeMode.System -> "Системная"; ThemeMode.Dark -> "Тёмная"; ThemeMode.Light -> "Светлая" } + if (theme == mode) " ✓" else "",
                            { onTheme(mode) }, Modifier.weight(1f))
                    }
                }
                V2CompactToggle("Цвета Android", dynamicColor, onDynamicColor)
            }
            V2NavRow("Доступность", "Крупный текст, контраст и виброотклик", onAccessibility)
            TextButton(onClick = { onStyle(AppBackgroundStyle.DeepSpace) }) { Text("Спокойный фон «Космос»${if (style == AppBackgroundStyle.DeepSpace) " ✓" else ""}", color = Aurora.Muted, fontSize = 11.sp) }
            Text("Фото хранится только на устройстве. При уменьшении анимации эффекты отключаются.", color = Aurora.Muted, fontSize = 10.sp)
        }
    }
}

@Composable
private fun V2AccessibilityPage(
    settings: UiSettings,
    onLargeText: (Boolean) -> Unit,
    onHighContrast: (Boolean) -> Unit,
    onReduceMotion: (Boolean) -> Unit,
    onHaptics: (Boolean) -> Unit,
    onBack: () -> Unit,
) {
    BackHandler { onBack() }
    V2AuroraBackdrop(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            TextButton(onClick = onBack) { Text("← Назад", color = Aurora.Mint) }
            V2AuroraHeader("Доступность", "Интерфейс под ваши привычки")
            V2Toggle("Крупный текст", "Системный размер шрифта сохраняется; добавляется ещё 15%", settings.largeText, onLargeText)
            V2Toggle("Высокий контраст", "Более чёткие границы, подписи и плотные карточки", settings.highContrast, onHighContrast)
            V2Toggle("Уменьшение анимации", "Без вращения, пульсации и пузырьков при касании", settings.reduceMotion, onReduceMotion)
            V2Toggle("Виброотклик", "Короткий отклик главной кнопки и навигации", settings.hapticsEnabled, onHaptics)
            V2GlassPanel(Modifier.fillMaxWidth()) {
                Text("TalkBack использует подписи кнопок Android. Крупный шрифт не скрывает действия: при необходимости экран можно прокрутить.", color = Aurora.Muted, fontSize = 13.sp, modifier = Modifier.padding(16.dp))
            }
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
internal fun V2BottomBar(tab: V2Tab, onTab: (V2Tab) -> Unit) {
    val density = LocalDensity.current
    // Honour the real Android gesture/three-button bar; bound broken OEM reports.
    val bottomClearance = with(density) { WindowInsets.navigationBars.getBottom(this).toDp() }.coerceIn(0.dp, 72.dp) + 12.dp
    Surface(
    color = Aurora.Night.copy(alpha = .97f),
    border = androidx.compose.foundation.BorderStroke(1.dp, Aurora.Border.copy(alpha = .74f)),
    shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
    shadowElevation = 14.dp,
    // Include the measured system bar once, with a bound for broken OEM insets.
    modifier = Modifier.fillMaxWidth().testTag("bottom-navigation").padding(bottom = bottomClearance),
) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 7.dp, vertical = 7.dp),
        horizontalArrangement = Arrangement.SpaceEvenly,
    ) {
        val navHaptic = Haptics.rememberPerformer(LocalAuroraHaptics.current)
        val fontScale = LocalDensity.current.fontScale
        // Cards is opened from the compact home shortcut. Keeping four fixed
        // bottom actions preserves tap targets on small Android screens.
        V2Tab.entries.filter { it != V2Tab.Cards }.forEach { item ->
            val selected = item == tab
            Surface(
                onClick = { navHaptic(Haptics.Click); onTab(item) },
                color = if (selected) Aurora.Mint.copy(alpha = .14f) else Color.Transparent,
                shape = RoundedCornerShape(16.dp),
                // The previous minimum-only height let fillMaxSize() in the
                // child Column consume the whole free screen height on some
                // devices.  That turned the selected tab into a tall stripe,
                // pushed the bar upward, and hid the page content.  A fixed
                // tab height keeps the complete bottom bar compact.
                modifier = Modifier.weight(1f).height((56f + (fontScale - 1f).coerceAtLeast(0f) * 16f).coerceAtMost(80f).dp).padding(horizontal = 2.dp).semantics { contentDescription = item.title },
            ) {
                Column(
                    Modifier.fillMaxSize().padding(vertical = 6.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    Icon(item.icon, contentDescription = item.title, tint = if (selected) Aurora.Mint else Aurora.Muted, modifier = Modifier.size(22.dp))
                    Text(item.title, color = if (selected) Aurora.Mint else Aurora.Muted, fontSize = 11.sp, maxLines = 1, overflow = TextOverflow.Ellipsis, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal)
                }
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
                fun curve(upload: Boolean): Path {
                    val path = Path()
                    samples.forEachIndexed { index, sample ->
                        val x = size.width * index / (samples.size - 1)
                        val bytes = if (upload) sample.uploadBytesPerSecond else sample.downloadBytesPerSecond
                        val y = size.height * (1 - bytes.coerceAtLeast(0L) / peak).coerceIn(0f, 1f)
                        if (index == 0) path.moveTo(x, y) else {
                            val prior = samples[index - 1]
                            val priorBytes = if (upload) prior.uploadBytesPerSecond else prior.downloadBytesPerSecond
                            val priorX = size.width * (index - 1) / (samples.size - 1)
                            val priorY = size.height * (1 - priorBytes.coerceAtLeast(0L) / peak).coerceIn(0f, 1f)
                            val middle = (priorX + x) / 2
                            // Horizontal controls interpolate measured samples without inventing peaks.
                            path.cubicTo(middle, priorY, middle, y, x, y)
                        }
                    }
                    return path
                }
                val down = curve(false)
                val up = curve(true)
                val fill = Path().apply { addPath(down); lineTo(size.width, size.height); lineTo(0f, size.height); close() }
                drawPath(fill, Brush.verticalGradient(listOf(mint.copy(alpha = .22f), mint.copy(alpha = .01f))))
                drawPath(down, mint, style = Stroke(2.5.dp.toPx()))
                drawPath(up, violet, style = Stroke(2.dp.toPx()))
            }
        }
    }
}
