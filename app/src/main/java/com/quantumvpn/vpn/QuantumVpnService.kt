package com.quantumvpn.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import com.quantumvpn.MainActivity
import com.quantumvpn.R
import com.quantumvpn.QuantumVpnApplication
import com.quantumvpn.config.ConfigAnalyzer
import com.quantumvpn.config.DnsMode
import com.quantumvpn.config.DnsOverride
import com.quantumvpn.config.OutboundDescription
import com.quantumvpn.config.BootstrapConfig
import com.quantumvpn.config.RuntimeConfigOptions
import com.quantumvpn.config.RuntimeConfigBuilder
import com.quantumvpn.config.SelectorGroup
import com.quantumvpn.diagnostics.EffectiveOverlaySummary
import com.quantumvpn.diagnostics.CoreDiagnosticBatchCollector
import com.quantumvpn.diagnostics.DiagnosticStageStatus
import com.quantumvpn.diagnostics.OperatorIngest
import com.quantumvpn.diagnostics.SecretRedactor
import com.quantumvpn.config.JsonConfig
import com.quantumvpn.config.RuntimeConfigResult
import com.quantumvpn.hardening.CarrierBypassHardening
import com.quantumvpn.hardening.BypassPreset
import com.quantumvpn.hardening.resolveBypassOptions
import com.quantumvpn.hardening.VpnHidingOptions
import com.quantumvpn.hardening.VpnRuntimeHardening
import kotlinx.serialization.json.JsonObject
import com.quantumvpn.routing.RoutingConfigEditor
import com.quantumvpn.networkbootstrap.CodedFailure
import io.nekohasekai.libbox.CommandClient
import io.nekohasekai.libbox.CommandClientHandler
import io.nekohasekai.libbox.CommandClientOptions
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.Connection
import io.nekohasekai.libbox.ConnectionEvents
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.LogIterator
import io.nekohasekai.libbox.OutboundGroupIterator
import io.nekohasekai.libbox.OverrideOptions
import io.nekohasekai.libbox.StatusMessage
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.SystemProxyStatus
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.math.min

private data class UnderlyingPolicyKey(
    val identity: String?,
    val captivePortal: Boolean,
    val strictPrivateDns: Boolean,
    val strictPrivateDnsServerName: String?,
    val strictPrivateDnsReady: Boolean,
)

private fun UnderlyingNetworkState.policyKey() = UnderlyingPolicyKey(
    identity = identity,
    captivePortal = captivePortal,
    strictPrivateDns = privateDnsMode == PrivateDnsMode.Strict,
    strictPrivateDnsServerName = privateDnsServerName.takeIf { privateDnsMode == PrivateDnsMode.Strict },
    strictPrivateDnsReady = privateDnsMode != PrivateDnsMode.Strict || (privateDnsActive && validated),
)

internal enum class NetworkRestartDecision {
    KeepSession,
    DebounceRestart,
}

internal object NetworkRestartPolicy {
    fun <T> decide(sessionBaseline: T, observed: T): NetworkRestartDecision =
        if (sessionBaseline == observed) {
            NetworkRestartDecision.KeepSession
        } else {
            NetworkRestartDecision.DebounceRestart
        }
}

internal object AutomaticDnsFallbackPolicy {
    fun candidates(configuredMode: DnsMode, hasProfileDns: Boolean): List<DnsMode> =
        if (configuredMode == DnsMode.Automatic) {
            buildList {
                if (hasProfileDns) add(DnsMode.FromJson)
                add(DnsMode.Android)
                add(DnsMode.Secure)
            }
        } else {
            listOf(configuredMode)
        }

    fun label(mode: DnsMode): String = when (mode) {
        DnsMode.FromJson -> "DNS профиля"
        DnsMode.Android -> "DNS Android"
        DnsMode.Secure -> "защищённый DoH"
        DnsMode.Automatic -> "автоматический DNS"
    }

    suspend fun <T> run(
        candidates: List<DnsMode>,
        onFallback: (from: DnsMode, to: DnsMode, failure: VpnDnsHealthException) -> Unit,
        attempt: suspend (DnsMode) -> T,
    ): T {
        require(candidates.isNotEmpty())
        for ((index, candidate) in candidates.withIndex()) {
            try {
                return attempt(candidate)
            } catch (error: VpnDnsHealthException) {
                if (index == candidates.lastIndex) throw error
                onFallback(candidate, candidates[index + 1], error)
            }
        }
        error("DNS fallback завершился без результата.")
    }
}

class QuantumVpnService : VpnService() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val serviceLock = Mutex()
    private val foregroundActive = AtomicBoolean(false)
    private val stopInProgress = AtomicBoolean(false)
    private val sessionStateLock = Any()
    private val lifecycleJobLock = Any()

    private val container by lazy { (application as QuantumVpnApplication).container }
    private val controller by lazy { container.vpnController }
    private val desireStore by lazy { VpnSessionDesireStore(this) }
    private var wakeLock: PowerManager.WakeLock? = null
    private val coreStopRecoveries = AtomicInteger(0)
    @Volatile
    private var activeSession: ActiveSession? = null
    @Volatile
    private var pendingSession: ActiveSession? = null
    private var lifecycleJob: Job? = null
    private var terminalError = false
    @Volatile
    private var everConnectedThisSession = false
    private val restartScheduleLock = Any()
    private var networkRestartJob: Job? = null
    @Volatile
    private var muteNotificationTrafficDetail: Boolean = false

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!foregroundActive.get()) showForeground(ForegroundNotificationState.Preparing)
        when (intent?.action) {
            ACTION_START -> {
                val profileId = intent.getStringExtra(EXTRA_PROFILE_ID).orEmpty()
                desireStore.markWanted(
                    profileId = profileId,
                    updaterRouting = intent.getBooleanExtra(EXTRA_UPDATER_ROUTING, false),
                )
                requestStart(
                    profileId = profileId,
                    startId = startId,
                    updaterRouting = intent.getBooleanExtra(EXTRA_UPDATER_ROUTING, false),
                )
            }
            ACTION_SELECT -> requestSelect(
                profileId = intent.getStringExtra(EXTRA_PROFILE_ID).orEmpty(),
                groupTag = intent.getStringExtra(EXTRA_GROUP_TAG).orEmpty(),
                outboundTag = intent.getStringExtra(EXTRA_OUTBOUND_TAG).orEmpty(),
                startId = startId,
            )
            ACTION_RESTART -> requestRestart(
                profileId = intent.getStringExtra(EXTRA_PROFILE_ID).orEmpty(),
                reason = intent.getStringExtra(EXTRA_REASON).orEmpty().ifBlank { "Перезапуск VPN" },
                startId = startId,
                noCacheLookup = false,
                updaterRouting = intent.takeIf { it.hasExtra(EXTRA_UPDATER_ROUTING) }
                    ?.getBooleanExtra(EXTRA_UPDATER_ROUTING, false),
            )
            ACTION_CLEAR_DNS_CACHE -> requestClearDnsCache(startId)
            ACTION_PING -> requestPing(startId)
            ACTION_PING_GROUP -> requestGroupPing(
                profileId = intent.getStringExtra(EXTRA_PROFILE_ID).orEmpty(),
                groupTag = intent.getStringExtra(EXTRA_GROUP_TAG).orEmpty(),
                startId = startId,
            )
            ACTION_STOP -> {
                desireStore.clear()
                releaseWakeLock()
                requestStop(startId, null)
            }
            else -> restoreOrIdle(startId)
        }
        // Sticky: Android may restart us after OEM kills / low memory with a null intent.
        return Service.START_STICKY
    }

    override fun onBind(intent: Intent): IBinder? = super.onBind(intent)

    override fun onTaskRemoved(rootIntent: Intent?) {
        // Swiping the app from Recents must NOT tear down the VPN session.
        super.onTaskRemoved(rootIntent)
        if (desireStore.read().wanted && activeSession == null && lifecycleJob?.isActive != true) {
            restoreOrIdle(startId = 0)
        }
    }

    override fun onRevoke() {
        desireStore.clear()
        releaseWakeLock()
        requestStop(
            startId = 0,
            errorMessage = "Разрешение Android VPN отозвано.",
            trigger = "permission_revoked",
        )
        super.onRevoke()
    }

    override fun onDestroy() {
        cancelScheduledNetworkRestart()
        controller.cancelCurrentConnectionDiagnostic()
        cancelLifecycleJob()
        val remaining = detachSessions()
        remaining.forEach(ActiveSession::closeTun)
        runBlocking(Dispatchers.IO) { remaining.forEach(ActiveSession::close) }
        serviceScope.cancel()
        releaseWakeLock()
        finishForeground()
        if (!terminalError) {
            controller.publish(controller.currentGeneration(), VpnConnectionState.Stopped)
        }
        super.onDestroy()
    }

    private fun restoreOrIdle(startId: Int) {
        val policy = VpnSystemPolicyDetector.detect(this)
        if (policy.blockingMessage != null) {
            desireStore.clear()
            releaseWakeLock()
            requestStop(startId, policy.blockingMessage, policy)
            return
        }
        if (activeSession != null || lifecycleJob?.isActive == true) {
            showForeground(
                if (activeSession != null) {
                    ForegroundNotificationState.Connected
                } else {
                    ForegroundNotificationState.Preparing
                },
            )
            return
        }
        val desire = desireStore.read()
        val profileId = desire.profileId?.takeIf { desire.wanted }
            ?: if (desire.wanted) {
                runBlocking { container.uiSettingsStore.settings.first().activeProfileId }
            } else {
                null
            }
        if (desire.wanted && !profileId.isNullOrBlank()) {
            requestStart(
                profileId = profileId,
                startId = startId,
                updaterRouting = desire.updaterRouting,
            )
            return
        }
        finishForeground()
        if (startId > 0) stopSelfResult(startId) else stopSelf()
    }

    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        val pm = getSystemService(PowerManager::class.java) ?: return
        val lock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "QuantumVPN:session").apply {
            setReferenceCounted(false)
            acquire(6 * 60 * 60 * 1000L) // refreshed while connected
        }
        wakeLock = lock
    }

    private fun releaseWakeLock() {
        runCatching {
            wakeLock?.takeIf { it.isHeld }?.release()
        }
        wakeLock = null
    }

    private fun requestStart(profileId: String, startId: Int, updaterRouting: Boolean) {
        stopInProgress.set(false)
        val token = controller.nextGeneration()
        terminalError = false
        everConnectedThisSession = false
        controller.beginConnectionDiagnostic(token, "user_start")
        controller.startConnectionDiagnosticStage(token, "profile", "Профиль и область приложений")
        controller.publish(
            token,
            VpnConnectionState.Starting(profileId, "Проверка профиля", updaterRouting),
        )
        showForeground(ForegroundNotificationState.ValidatingProfile)
        trackLifecycleJob(serviceScope.launch {
            serviceLock.withLock {
                detachSessions().forEach(ActiveSession::close)
                if (token != controller.currentGeneration()) return@withLock
                try {
                    startWithDeadline(token, profileId, updaterRouting = updaterRouting)
                } catch (error: Throwable) {
                    if (token == controller.currentGeneration()) {
                        failLocked(token, error, startId)
                    }
                }
            }
        })
    }

    private suspend fun startLocked(
        token: Long,
        profileId: String,
        noCacheLookup: Boolean = false,
        updaterRouting: Boolean = false,
        runtimeDnsMode: DnsMode? = null,
    ) {
        require(profileId.isNotBlank()) { "Профиль не выбран." }
        val systemPolicy = VpnSystemPolicyDetector.detect(this)
        controller.publishVpnSystemPolicy(token, systemPolicy)
        systemPolicy.blockingMessage?.let(::error)
        container.libboxRuntime.initialize().getOrThrow()
        container.profileStore.initialize()
        var profile = container.profileStore.read(profileId)
        if (RoutingConfigEditor.usesManagedLocalRuleSets(profile.json)) {
            val installed = container.ruleSetAssetManager.ensureInstalled()
            val rebound = RoutingConfigEditor.rebindManagedRuleSetPaths(profile.json, installed)
            if (rebound != profile.json) {
                container.profileStore.update(profileId, rebound)
                profile = container.profileStore.read(profileId)
            }
        }
        // Перед сборкой runtime: Maximum + AdGuard + Safe mode off (без UI из сервиса).
        runCatching {
            com.quantumvpn.hardening.AdBlockConnectPreflight.prepare(
                context = this,
                settingsStore = container.uiSettingsStore,
                openPrivateDnsSettingsIfStrict = false,
            )
        }
        val uiSettings = container.uiSettingsStore.settings.first()
        muteNotificationTrafficDetail = uiSettings.muteNotificationTrafficDetail
        val configuredDnsMode = uiSettings.dnsMode
        val safeMode = uiSettings.safeModeConnect
        val dnsMode = when {
            runtimeDnsMode != null -> runtimeDnsMode
            safeMode -> DnsMode.Android
            else -> configuredDnsMode
        }
        check(dnsMode != DnsMode.Automatic) {
            "Автоматический DNS должен быть разрешён в один runtime-кандидат до запуска core."
        }
        val vpnHiding = if (safeMode) {
            VpnHidingOptions(blockLocalEndpoints = true)
        } else {
            uiSettings.vpnHiding
        }
        val carrier = CarrierDetector.snapshot(this)
        // DPI bypass is always on for every carrier (except safe mode).
        val preset = when {
            safeMode -> BypassPreset.Soft
            !carrier.isCellular &&
                uiSettings.softerBypassOnWifi &&
                uiSettings.bypassPreset == BypassPreset.Aggressive ->
                BypassPreset.Tele2
            carrier.isCellular &&
                (uiSettings.bypassPreset == BypassPreset.Standard ||
                    uiSettings.bypassPreset == BypassPreset.Soft) ->
                BypassPreset.Tele2
            else -> uiSettings.bypassPreset
        }
        val carrierBypass = resolveBypassOptions(
            enabled = !safeMode,
            preset = preset,
            alwaysAggressive = uiSettings.carrierBypassAlwaysAggressive ||
                preset == BypassPreset.Tele2 ||
                preset == BypassPreset.Aggressive,
        )
        val panelAllowsAdblock = com.quantumvpn.policy.ClientFeatureGate.features().adblock
        // Всегда включаем блокировку при обычном connect (после preflight).
        val adBlockEnabled = !safeMode && panelAllowsAdblock
        val whitelist = uiSettings.adBlockWhitelist
            .split(',', ' ', '\n', ';')
            .map { it.trim().lowercase() }
            .filter { it.isNotBlank() }
        // Runtime всегда Maximum + онлайн AdGuard, пока ad-block разрешён.
        val effectiveLevel = if (adBlockEnabled) {
            com.quantumvpn.hardening.AdBlockLevel.Maximum
        } else {
            uiSettings.adBlockLevel
        }
        val adBlockOptions = com.quantumvpn.hardening.AdBlockOptions(
            enabled = adBlockEnabled,
            level = effectiveLevel,
            trackersOnly = false,
            whitelistSuffixes = whitelist,
            useOnlineFilterDns = adBlockEnabled,
            categories = uiSettings.adBlockCategories,
        )
        if (dnsMode == DnsMode.FromJson) {
            ConfigAnalyzer.dnsWarnings(profile.json).forEach(controller::publishDiagnosticWarning)
        }
        if (safeMode) {
            controller.publishDiagnosticWarning(
                "Safe mode: минимальный runtime (Android DNS, без bootstrap и overrides).",
            )
        }
        if (carrierBypass.enabled) {
            val modeLabel = when (carrierBypass.preset) {
                BypassPreset.Soft -> "мягкий"
                BypassPreset.Standard -> "стандарт"
                BypassPreset.Tele2 -> "оператор (все сети)"
                BypassPreset.Aggressive -> "агрессивный"
            }
            val carrierHint = carrier.displayLabel?.let { " · $it" }.orEmpty()
            controller.publishDiagnosticWarning(
                "Обход DPI$carrierHint: $modeLabel — VLESS/Trojan/Hysteria/TUIC; Reality без ClientHello-fragment.",
            )
        }
        if (adBlockEnabled) {
            val ruleCount = com.quantumvpn.hardening.AdBlockHardening.ruleCount(adBlockOptions)
            val online = if (adBlockOptions.useOnlineFilterDns) " + AdGuard DoH онлайн" else ""
            controller.publishDiagnosticWarning(
                "Блокировка рекламы: DNS reject + перехват DNS + маршрут ($ruleCount правил$online). " +
                    "Работает для всех приложений в VPN.",
            )
        } else if (uiSettings.adBlockEnabled && !panelAllowsAdblock) {
            controller.publishDiagnosticWarning(
                "Блокировка рекламы отключена политикой панели.",
            )
        } else if (uiSettings.adBlockEnabled && safeMode) {
            controller.publishDiagnosticWarning(
                "Safe mode: блокировка рекламы выключена.",
            )
        }
        // Per-app scope from user settings (All = full device VPN).
        val selection = container.appSelectionStore.selection.first()
        val selectedPackages = selection.allowedPackages
        val scopeMode = selection.mode
        val preflight = container.vpnAppScopePreflight.apply(
            selectedPackages = selectedPackages,
            mode = scopeMode,
            allowedSink = AllowedApplicationSink { },
            disallowedSink = DisallowedApplicationSink { },
        )
        val effectivePackages = when (preflight) {
            is VpnAppScopeResult.Ready -> {
                if (preflight.skippedPackages.isNotEmpty()) {
                    controller.publishDiagnosticWarning(
                        "Пропущены недоступные приложения: " +
                            preflight.skippedPackages.joinToString(),
                    )
                }
                preflight.effectivePackages
            }
            VpnAppScopeResult.EmptyAllowlist -> error("Выберите хотя бы одно приложение для VPN.")
            is VpnAppScopeResult.MissingApplications -> error(
                "Не осталось доступных выбранных приложений. Выберите хотя бы одно.",
            )
            is VpnAppScopeResult.BuilderFailure -> error(
                "Android отклонил приложение ${preflight.packageName}: ${preflight.reason}",
            )
        }

        controller.startConnectionDiagnosticStage(token, "android_network", "Сеть и политика Android")
        controller.publish(
            token,
            VpnConnectionState.Starting(profileId, "Проверка сети Android", updaterRouting),
        )
        showForeground(ForegroundNotificationState.CheckingNetwork)
        val networkMonitor = DefaultNetworkMonitor(this).also(DefaultNetworkMonitor::start)
        controller.startConnectionDiagnosticStage(token, "bootstrap", "Bootstrap DNS и доступность сервера")
        val networkBootstrap = try {
            networkMonitor.runOnStableNetwork { candidate ->
                val underlying = if (VpnTestHooks.consumeCaptivePortalOverride()) {
                    candidate.copy(captivePortal = true, validated = false)
                } else {
                    candidate
                }
                controller.publishDiagnosticNetwork(token, underlying)
                if (underlying.captivePortal) {
                    error("Интернет требует авторизации в Wi-Fi.")
                }
                if (underlying.privateDnsMode == PrivateDnsMode.Strict &&
                    (configuredDnsMode == DnsMode.Automatic || configuredDnsMode == DnsMode.Secure)
                ) {
                    error("Strict Private DNS несовместим с этим режимом. Выберите «DNS Android» или «Из JSON».")
                }
                if (underlying.privateDnsMode == PrivateDnsMode.Strict &&
                    dnsMode == DnsMode.Android &&
                    (!underlying.privateDnsActive || !underlying.validated)
                ) {
                    error("Strict Private DNS не отвечает. Исправьте системную настройку или выберите «Из JSON».")
                }
                container.proxyBootstrapper.prepare(
                    profileId = profileId,
                    rawJson = profile.json,
                    underlying = checkNotNull(underlying.network),
                    noCacheLookup = noCacheLookup,
                )
            }
        } catch (error: Throwable) {
            networkMonitor.close()
            throw error
        }
        val underlying = networkBootstrap.network
        val preparedBootstrap = networkBootstrap.value

        controller.startConnectionDiagnosticStage(token, "runtime_config", "Runtime overlay")
        val runtimeJson = try {
            when (
                val runtime = RuntimeConfigBuilder.build(
                    profile.json,
                    enableTrafficStats = true,
                    options = RuntimeConfigOptions(
                        dnsMode = dnsMode,
                        proxyIpv4Only = uiSettings.proxyIpv4Only,
                        dnsOverride = if (safeMode) DnsOverride() else uiSettings.dnsOverride,
                        bootstrapHost = if (safeMode) null else preparedBootstrap.overlay,
                        vpnHiding = vpnHiding,
                        carrierBypass = carrierBypass,
                        adBlockEnabled = adBlockEnabled,
                        adBlockOptions = adBlockOptions,
                        blockWebRtcMdns = !safeMode && uiSettings.blockWebRtcMdns,
                        healthCheckPackageName = packageName,
                        updaterPackageName = packageName.takeIf { updaterRouting },
                        customDohUrl = uiSettings.customDohUrl.takeIf { it.isNotBlank() },
                        blockedPackageNames = if (scopeMode == AppScopeMode.Block) {
                            effectivePackages.filter { it != packageName }
                        } else {
                            emptyList()
                        },
                    ),
                )
            ) {
                is RuntimeConfigResult.Ready -> runtime.json
                is RuntimeConfigResult.Invalid -> error(runtime.message)
            }
        } catch (error: Throwable) {
            networkMonitor.close()
            OperatorIngest.postRedacted(
                this,
                "connect_runtime_error",
                mapOf(
                    "profile" to profileId,
                    "error" to (error.message ?: error.javaClass.simpleName),
                    "carrier" to (carrier.operatorNumeric ?: "unknown"),
                    "tele2" to carrier.isTele2Family.toString(),
                    "bypass" to carrierBypass.enabled.toString(),
                ),
            )
            throw error
        }
        controller.publishEffectiveOverlay(
            token,
            EffectiveOverlaySummary.create(
                runtimeJson,
                dnsMode,
                carrierBypassEnabled = carrierBypass.enabled,
                carrierBypassAggressive = carrierBypass.aggressive,
                carrierNumeric = carrier.operatorNumeric,
            ),
        )
        if (carrierBypass.enabled) {
            val presence = runCatching {
                CarrierBypassHardening.inspect(JsonConfig.parse(runtimeJson) as JsonObject)
            }.getOrNull()
            when {
                presence != null &&
                    presence.tlsFragmentOutboundCount == 0 &&
                    presence.udpFragmentOutboundCount == 0 &&
                    !presence.routeOptionsPresent -> {
                    controller.publishDiagnosticWarning(
                        "Обход DPI не к чему применить: нет TLS/Hysteria-прокси. " +
                            "Чистый WireGuard почти не получает fragment.",
                    )
                }
                presence != null &&
                    presence.tlsFragmentOutboundCount == 0 &&
                    presence.udpFragmentOutboundCount > 0 -> {
                    controller.publishDiagnosticWarning(
                        "Обход DPI: udp_fragment на Hysteria/TUIC (${presence.udpFragmentOutboundCount}).",
                    )
                }
                presence != null && presence.tlsFragmentOutboundCount == 0 -> {
                    controller.publishDiagnosticWarning(
                        "Обход DPI: route-options включены; TLS-прокси в профиле нет.",
                    )
                }
            }
        }
        controller.startConnectionDiagnosticStage(token, "check_config", "Проверка конфигурации ядром")
        controller.publish(
            token,
            VpnConnectionState.Starting(profileId, "Проверка sing-box", updaterRouting),
        )
        showForeground(ForegroundNotificationState.ValidatingCore)
        try {
            Libbox.checkConfig(runtimeJson)
            check(token == controller.currentGeneration()) { "Запуск отменён." }
        } catch (error: Throwable) {
            networkMonitor.close()
            throw error
        }

        controller.startConnectionDiagnosticStage(token, "platform_adapter", "Подготовка Android VPN adapter")
        controller.publish(
            token,
            VpnConnectionState.Starting(profileId, "Создание TUN", updaterRouting),
        )
        showForeground(ForegroundNotificationState.CreatingTun)
        val resources = ActiveSession(
            profileId = profileId,
            profileName = profile.metadata.name,
            generation = token,
            networkMonitor = networkMonitor,
            networkPolicyKey = underlying.policyKey(),
            outboundDescriptions = ConfigAnalyzer.outboundDescriptions(profile.json),
            selectorGroups = ConfigAnalyzer.outboundGroups(profile.json),
            updaterRouting = updaterRouting,
            controller = controller,
            onTrafficRate = ::updateTrafficNotification,
        )
        if (!registerPendingSession(resources, token)) {
            resources.close()
            throw CancellationException("Запуск отменён.")
        }
        try {
            resources.attachPlatform(AndroidPlatformAdapter(
                service = this,
                selectedPackages = selectedPackages,
                scopeMode = scopeMode,
                expectedPackages = effectivePackages,
                scopePreflight = container.vpnAppScopePreflight,
                networkMonitor = networkMonitor,
                sessionName = VpnRuntimeHardening.sessionName(vpnHiding),
                blockNonVpnTraffic = uiSettings.blockNonVpnTraffic,
            ))
            controller.startConnectionDiagnosticStage(token, "command_server", "Запуск локального command server")
            val commandServer = Libbox.newCommandServer(
                ServerHandler(this),
                resources.platform(),
            )
            resources.attachServer(commandServer)
            commandServer.start()
            controller.startConnectionDiagnosticStage(token, "core_service", "Запуск sing-box и создание TUN")
            commandServer.startOrReloadService(
                runtimeJson,
                OverrideOptions().apply {
                    includePackage = ListStringIterator(emptyList())
                    excludePackage = ListStringIterator(emptyList())
                    autoRedirect = false
                },
            )
            resources.markLibboxStarted()
            check(token == controller.currentGeneration()) { "Запуск отменён." }

            // Subscribe before any startup probe. The command server retains a bounded
            // backlog, so handshake, transport and DNS failures remain available even
            // when health verification fails and the session is closed immediately.
            controller.startConnectionDiagnosticStage(token, "core_log", "Снимок bounded core-лога")
            resources.openLogClient(controller)
            controller.startConnectionDiagnosticStage(token, "group_client", "Чтение selector-групп")
            val groupClient = Libbox.newCommandClient(
                GroupClientHandler(
                    controller,
                    token,
                    resources.outboundDescriptions,
                ),
                CommandClientOptions().apply {
                    addCommand(Libbox.CommandGroup)
                },
            )
            resources.attachClient(groupClient)
            groupClient.connect()
            check(token == controller.currentGeneration()) { "Запуск отменён." }
            // Mark Connected as soon as TUN + core are up. DNS/HTTPS probes must not
            // delay the session (previously could wait ~24s on soft timeout).
            controller.startConnectionDiagnosticStage(token, "finalize", "Финализация сессии")
            container.proxyBootstrapper.recordSuccess(profileId, preparedBootstrap)
            check(activatePendingSession(resources, token)) { "Запуск отменён." }
            resources.attachNetworkObserver(networkMonitor.observe { state ->
                onUnderlyingNetworkEvent(resources, state)
            })
            controller.publish(
                token,
                VpnConnectionState.Connected(
                    profileId = profileId,
                    profileName = profile.metadata.name,
                    connectedAtEpochMillis = System.currentTimeMillis(),
                    updaterRouting = updaterRouting,
                ),
            )
            everConnectedThisSession = true
            OperatorIngest.postRedacted(
                this,
                "connected",
                mapOf(
                    "profile" to profileId,
                    "carrier" to (carrier.operatorNumeric ?: "unknown"),
                    "tele2" to carrier.isTele2Family.toString(),
                    "cellular" to carrier.isCellular.toString(),
                    "bypass" to carrierBypass.enabled.toString(),
                    "aggressive" to carrierBypass.aggressive.toString(),
                    "dns" to dnsMode.name,
                ),
            )
            startHomeStatusObserver(resources)
            startDiagnosticsObserver(resources)
            if (!controller.diagnosticsVisible.value) resources.closeLogClient(controller)
            startConnectionIdentityProbe(resources)
            startTrafficWatchdog(resources, token, profileId)
            scheduleDeferredHealthCheck(resources, dnsMode, token)
        } catch (error: Throwable) {
            discardSession(resources)
            resources.close()
            throw error
        }

        if (token == controller.currentGeneration() && activeSession === resources) {
            showForeground(ForegroundNotificationState.Connected)
            desireStore.markWanted(profileId, updaterRouting)
            acquireWakeLock()
            coreStopRecoveries.set(0)
        }
    }

    /** Non-blocking post-connect probe; never delays or tears down the session. */
    private fun scheduleDeferredHealthCheck(
        session: ActiveSession,
        dnsMode: DnsMode,
        token: Long,
    ) {
        serviceScope.launch {
            try {
                val dnsServer = session.platform().internalDnsServer ?: return@launch
                val proxyIpFamily = BootstrapConfig.selectedProxyIpFamily(
                    container.profileStore.read(session.profileId).json,
                )
                withTimeout(DEFERRED_HEALTH_TIMEOUT_MILLIS) {
                    container.vpnHealthPipeline.verify(
                        mode = dnsMode,
                        internalDnsServer = dnsServer,
                        proxyIpFamily = proxyIpFamily,
                        onStageStarted = { stage ->
                            controller.startConnectionDiagnosticStage(
                                token,
                                stage.diagnosticKey,
                                stage.diagnosticLabel,
                            )
                        },
                        onStageFinished = { stage, outcome, detail ->
                            controller.finishConnectionDiagnosticStage(
                                generation = token,
                                key = stage.diagnosticKey,
                                status = when (outcome) {
                                    VpnHealthStageOutcome.Success -> DiagnosticStageStatus.Success
                                    VpnHealthStageOutcome.Recovered -> DiagnosticStageStatus.Recovered
                                    VpnHealthStageOutcome.Failed -> DiagnosticStageStatus.Failed
                                },
                                detail = detail,
                            )
                        },
                    )
                }
            } catch (_: CancellationException) {
                // Session stopped or deferred window elapsed — ignore.
            } catch (_: Throwable) {
                // Never fail a live session because of a background probe.
            }
        }
    }

    private suspend fun startWithDeadline(
        token: Long,
        profileId: String,
        noCacheLookup: Boolean = false,
        updaterRouting: Boolean = false,
    ) {
        val completed = withTimeoutOrNull(CONNECTION_START_TIMEOUT_MILLIS) {
            val configuredMode = container.uiSettingsStore.settings.first().dnsMode
            container.profileStore.initialize()
            val hasProfileDns = configuredMode == DnsMode.Automatic &&
                ConfigAnalyzer.hasProfileDns(container.profileStore.read(profileId).json)
            val candidates = AutomaticDnsFallbackPolicy.candidates(configuredMode, hasProfileDns)
            AutomaticDnsFallbackPolicy.run(
                candidates = candidates,
                onFallback = { previous, candidate, failure ->
                    val failureType = generateSequence<Throwable>(failure) { it.cause }
                        .last()
                        .javaClass
                        .simpleName
                        .take(80)
                    val detail = "Автоматический DNS: ${AutomaticDnsFallbackPolicy.label(previous)} " +
                        "не отвечает ($failureType); пробуем ${AutomaticDnsFallbackPolicy.label(candidate)}."
                    controller.publishDiagnosticWarning(detail)
                    controller.startConnectionDiagnosticStage(
                        token,
                        "dns_fallback_${candidate.name.lowercase()}",
                        "DNS fallback: ${AutomaticDnsFallbackPolicy.label(candidate)}",
                    )
                    controller.publish(
                        token,
                        VpnConnectionState.Starting(profileId, detail, updaterRouting),
                    )
                },
                attempt = { candidate ->
                    startLocked(
                        token = token,
                        profileId = profileId,
                        noCacheLookup = noCacheLookup,
                        updaterRouting = updaterRouting,
                        runtimeDnsMode = candidate,
                    )
                    true
                },
            )
        } == true
        if (!completed) throw ConnectionStartupTimeoutException()
    }

    private fun requestRestart(
        profileId: String,
        reason: String,
        startId: Int,
        noCacheLookup: Boolean,
        updaterRouting: Boolean? = null,
    ) {
        stopInProgress.set(false)
        val token = controller.nextGeneration()
        trackLifecycleJob(serviceScope.launch {
            serviceLock.withLock {
                if (token != controller.currentGeneration()) return@withLock
                val targetProfile = activeSession?.profileId ?: profileId
                val targetUpdaterRouting = updaterRouting ?: activeSession?.updaterRouting ?: false
                if (targetProfile.isBlank()) {
                    controller.publishMessage("VPN выключен; перезапуск не требуется.")
                    finishForeground()
                    stopSelfResult(startId)
                    return@withLock
                }
                terminalError = false
                controller.beginConnectionDiagnostic(token, restartDiagnosticTrigger(reason))
                controller.startConnectionDiagnosticStage(
                    token,
                    "profile",
                    "Профиль и область приложений",
                )
                controller.publish(
                    token,
                    VpnConnectionState.Starting(targetProfile, reason, targetUpdaterRouting),
                )
                showForeground(ForegroundNotificationState.Restarting)
                detachSessions().forEach(ActiveSession::close)
                try {
                    startWithDeadline(
                        token,
                        targetProfile,
                        noCacheLookup,
                        updaterRouting = targetUpdaterRouting,
                    )
                } catch (error: Throwable) {
                    if (token == controller.currentGeneration()) failLocked(token, error, startId)
                }
            }
        })
    }

    private fun requestClearDnsCache(startId: Int) {
        serviceScope.launch {
            container.bootstrapCache.clear()
            val profileId = serviceLock.withLock { activeSession?.profileId.orEmpty() }
            if (profileId.isBlank()) {
                controller.publishMessage("Bootstrap cache очищен; системный DNS-кэш Android не изменён.")
                finishForeground()
                stopSelfResult(startId)
            } else {
                requestRestart(
                    profileId = profileId,
                    reason = "Сброс DNS-состояния",
                    startId = startId,
                    noCacheLookup = true,
                )
            }
        }
    }

    private fun onUnderlyingNetworkEvent(session: ActiveSession, state: UnderlyingNetworkState) {
        if (activeSession !== session) return
        controller.publishDiagnosticNetwork(session.generation, state)
        val nextPolicyKey = state.policyKey()
        if (
            NetworkRestartPolicy.decide(session.networkPolicyKey, nextPolicyKey) ==
            NetworkRestartDecision.KeepSession
        ) {
            cancelScheduledNetworkRestart()
            return
        }
        synchronized(restartScheduleLock) {
            networkRestartJob?.cancel()
            networkRestartJob = serviceScope.launch {
                delay(NETWORK_RESTART_DEBOUNCE_MILLIS)
                val current = activeSession
                if (current !== session || current.generation != controller.currentGeneration()) return@launch
                if (
                    NetworkRestartPolicy.decide(
                        current.networkPolicyKey,
                        current.networkMonitor.current.policyKey(),
                    ) == NetworkRestartDecision.KeepSession
                ) {
                    return@launch
                }
                requestRestart(
                    profileId = current.profileId,
                    reason = "Смена сети Android",
                    startId = 0,
                    noCacheLookup = false,
                )
            }
        }
    }

    private fun restartDiagnosticTrigger(reason: String): String = when (reason) {
        "Смена сети Android" -> "network_change"
        "Сброс DNS-состояния" -> "dns_cache_clear"
        "Изменение маршрутизации" -> "routing_change"
        "Подписка обновлена пользователем" -> "subscription_refresh"
        "Смена режима DNS" -> "dns_mode_change"
        "Смена IP-стратегии DNS" -> "dns_strategy_change"
        "Смена защиты от localhost-чекеров" -> "endpoint_policy_change"
        "Смена имени VPN-сессии" -> "session_name_change"
        "Смена MTU для скрытия VPN" -> "mtu_change"
        else -> "restart"
    }

    private fun requestStop(
        startId: Int,
        errorMessage: String?,
        systemPolicy: VpnSystemPolicy? = null,
        trigger: String = if (errorMessage == null) "user_stop" else "policy_stop",
        clearDesire: Boolean = errorMessage == null || trigger == "permission_revoked" || trigger == "policy_stop",
    ) {
        if (!stopInProgress.compareAndSet(false, true)) return
        if (clearDesire) desireStore.clear()
        releaseWakeLock()
        cancelScheduledNetworkRestart()
        controller.cancelCurrentConnectionDiagnostic()
        val token = controller.nextGeneration()
        controller.beginStopDiagnostic(token, trigger)
        systemPolicy?.let { controller.publishVpnSystemPolicy(token, it) }
        terminalError = errorMessage != null
        val sessions = detachSessions()
        sessions.forEach { it.enableStopDiagnostics(token) }
        val profileId = sessions.firstOrNull()?.profileId

        controller.startStopDiagnosticStage(token, "cancel_run", "Отмена текущего запуска")
        cancelLifecycleJob()
        controller.finishStopDiagnosticStage(token, "cancel_run")

        controller.publish(token, VpnConnectionState.Stopping(profileId))
        showForeground(ForegroundNotificationState.Stopping)
        sessions.forEach(ActiveSession::closeTun)
        serviceScope.launch {
            sessions.forEach(ActiveSession::close)
            if (sessions.isEmpty()) {
                listOf(
                    "close_tun" to "Закрытие Android TUN",
                    "close_clients" to "Отключение клиентов libbox",
                    "close_libbox_service" to "Остановка сервиса libbox",
                ).forEach { (key, label) ->
                    controller.startStopDiagnosticStage(token, key, label)
                    controller.finishStopDiagnosticStage(token, key)
                }
            }
            controller.completeStopDiagnostic(token)
            finishForeground()
            if (startId > 0) stopSelfResult(startId) else stopSelf()
            if (errorMessage == null) {
                controller.publish(token, VpnConnectionState.Stopped)
            } else {
                controller.publish(token, VpnConnectionState.Error(errorMessage))
            }
        }
    }

    private fun requestSelect(
        profileId: String,
        groupTag: String,
        outboundTag: String,
        startId: Int,
    ) {
        trackLifecycleJob(serviceScope.launch {
            serviceLock.withLock {
                val session = activeSession
                if (session == null || session.profileId != profileId) {
                    failLocked(
                        controller.currentGeneration(),
                        IllegalStateException("Активный VPN-профиль не найден."),
                        startId,
                    )
                    return@withLock
                }
                try {
                    selectLocked(session, groupTag, outboundTag)
                    showForeground(ForegroundNotificationState.Connected)
                    controller.clearConnectionIdentity(session.generation)
                    startConnectionIdentityProbe(session)
                } catch (runtimeSwitchError: RuntimeSwitchException) {
                    val restartToken = controller.nextGeneration()
                    controller.beginConnectionDiagnostic(restartToken, "server_switch_restart")
                    controller.startConnectionDiagnosticStage(
                        restartToken,
                        "profile",
                        "Профиль и область приложений",
                    )
                    controller.publish(
                        restartToken,
                        VpnConnectionState.Starting(
                            profileId,
                            "Перезапуск после смены сервера",
                            session.updaterRouting,
                        ),
                    )
                    showForeground(ForegroundNotificationState.Restarting)
                    detachSessions().forEach(ActiveSession::close)
                    try {
                        startWithDeadline(
                            restartToken,
                            profileId,
                            updaterRouting = session.updaterRouting,
                        )
                    } catch (restartError: Throwable) {
                        if (restartToken == controller.currentGeneration()) {
                            restartError.addSuppressed(runtimeSwitchError)
                            failLocked(restartToken, restartError, startId)
                        }
                    }
                } catch (validationError: Throwable) {
                    controller.publishMessage(safeError(validationError).message)
                    showForeground(ForegroundNotificationState.Connected)
                }
            }
        })
    }

    private fun requestPing(startId: Int) {
        serviceScope.launch {
            val session = serviceLock.withLock { activeSession }
            if (session == null) {
                controller.publishMessage("Сначала подключите VPN.")
                return@launch
            }
            val target = session.selectedPingTarget(controller.selectorGroups.value)
            runCatching {
                requireNotNull(target) { "У выбранного VPN-сервера нет адреса для ICMP." }
                measureServerPing(session, target)
            }
                .onSuccess { ping ->
                    if (activeSession === session) {
                        controller.publishServerPing(session.generation, checkNotNull(target).outboundTag, ping)
                        controller.publishPing(session.generation, ping)
                    }
                }
                .onFailure {
                    if (activeSession === session && target != null) {
                        controller.publishServerPing(session.generation, target.outboundTag, null)
                        controller.publishPing(session.generation, null)
                    }
                    controller.publishMessage("Не удалось измерить пинг: ${safeError(it).message}")
                }
        }
    }

    private fun requestGroupPing(profileId: String, groupTag: String, startId: Int) {
        serviceScope.launch {
            val session = serviceLock.withLock { activeSession }
            if (session == null || session.profileId != profileId) {
                controller.publishMessage("Активный VPN-профиль не найден.")
                return@launch
            }
            runCatching {
                require(groupTag.isNotBlank()) { "Группа серверов не выбрана." }
                val targets = session.groupPingTargets(groupTag, controller.selectorGroups.value)
                require(targets.isNotEmpty()) { "В группе нет серверов с адресом для ICMP." }
                val results = session.networkMonitor.runOnStableNetwork { underlying ->
                    val network = requireNotNull(underlying.network) { "Основная сеть Android недоступна." }
                    val concurrency = Semaphore(GROUP_PING_CONCURRENCY)
                    coroutineScope {
                        targets.map { target ->
                            async {
                                concurrency.withPermit {
                                    target to runCatching { container.icmpPingProbe.measure(network, target) }.getOrNull()
                                }
                            }
                        }.awaitAll()
                    }
                }.value
                results.forEach { (target, ping) ->
                    controller.publishServerPing(session.generation, target.outboundTag, ping)
                }
                val selected = session.selectedPingTarget(controller.selectorGroups.value)
                results.firstOrNull { it.first.outboundTag == selected?.outboundTag }?.let { (_, ping) ->
                    controller.publishPing(session.generation, ping)
                }
            }.onFailure {
                controller.publishMessage("Не удалось проверить серверы: ${safeError(it).message}")
            }
        }
    }

    private fun startHomeStatusObserver(session: ActiveSession) {
        // Статус-клиент всегда открыт в активной сессии: нужен для тарифа в уведомлении.
        session.attachStatusObserver(serviceScope.launch {
            session.openStatusClient(controller)
            try {
                awaitCancellation()
            } finally {
                if (activeSession === session) {
                    session.closeStatusClient(controller)
                }
            }
        })
    }

    private fun startDiagnosticsObserver(session: ActiveSession) {
        session.attachDiagnosticsObserver(serviceScope.launch {
            controller.diagnosticsVisible.collect { visible ->
                if (activeSession !== session) return@collect
                if (visible) {
                    session.openLogClient(controller)
                } else {
                    session.closeLogClient(controller)
                }
            }
        })
    }

    private fun startTrafficWatchdog(
        session: ActiveSession,
        token: Long,
        profileId: String,
    ) {
        session.replaceTrafficWatchdogJob(serviceScope.launch {
            delay(45_000L)
            if (activeSession !== session || token != controller.currentGeneration()) return@launch
            val stats = controller.sessionStats.value
            val total = stats.downloadTotalBytes + stats.uploadTotalBytes
            if (total > 8_192L) return@launch
            controller.publishMessage(
                "Мало трафика за 45 с. Проверьте сервер/протокол или нажмите «Сброс сети».",
            )
            controller.publishDiagnosticWarning(
                "Watchdog: почти нет байт через VPN (профиль $profileId). " +
                    "Для Hysteria/VLESS включите обход DPI; WireGuard на операторах слабее.",
            )
        })
    }

    private fun startConnectionIdentityProbe(session: ActiveSession) {
        session.replaceIdentityJob(serviceScope.launch {
            coroutineScope {
                launch {
                    val target = session.selectedPingTarget(controller.selectorGroups.value)
                    val ping = target?.let { runCatching { measureServerPing(session, it) }.getOrNull() }
                    if (activeSession === session && target != null) {
                        controller.publishServerPing(session.generation, target.outboundTag, ping)
                        controller.publishPing(session.generation, ping)
                    }
                }
                launch {
                    val identity = runCatching { container.vpnExternalIpProbe.fetchIdentity() }.getOrNull()
                    if (identity != null && activeSession === session) {
                        controller.publishExitIdentity(
                            session.generation,
                            identity.ip,
                            identity.location,
                        )
                    }
                }
            }
        })
    }

    private suspend fun measureServerPing(
        session: ActiveSession,
        target: ServerPingTarget,
    ): Long = session.networkMonitor.runOnStableNetwork { underlying ->
        val network = requireNotNull(underlying.network) { "Основная сеть Android недоступна." }
        container.icmpPingProbe.measure(network, target)
    }.value

    private suspend fun selectLocked(
        session: ActiveSession,
        groupTag: String,
        outboundTag: String,
    ) {
        require(groupTag.isNotBlank() && outboundTag.isNotBlank()) { "Сервер не выбран." }
        val stored = container.profileStore.read(session.profileId)
        val candidate = ConfigAnalyzer.selectServer(stored.json, groupTag, outboundTag)
        withContext(Dispatchers.Default) { Libbox.checkConfig(candidate) }
        container.profileStore.update(session.profileId, candidate)
        val client = session.client() ?: error("Клиент управления sing-box недоступен.")
        try {
            client.selectOutbound(groupTag, outboundTag)
        } catch (error: Throwable) {
            throw RuntimeSwitchException(error)
        }
        controller.publishSelection(session.generation, groupTag, outboundTag)
    }

    private suspend fun failLocked(token: Long, error: Throwable, startId: Int) {
        cancelScheduledNetworkRestart()
        detachSessions().forEach(ActiveSession::close)
        terminalError = true
        val failure = safeError(error)
        finishForeground()
        controller.publish(token, failure)
        if (startId > 0) stopSelfResult(startId) else stopSelf()
    }

    internal fun requestStopFromCore() {
        val desire = desireStore.read()
        val profileId = activeSession?.profileId ?: desire.profileId
        // Только восстанавливаем уже установленное соединение (которое дошло до Connected).
        // Если ядро останавливается во время начального подключения — это реальная ошибка
        // старта, а не сбой работающего туннеля: не делаем тихий перезапуск (раньше давал
        // видимый «перезапуск через ~1 с» сразу после нажатия Подключить).
        if (desire.wanted && everConnectedThisSession && !profileId.isNullOrBlank() && !stopInProgress.get()) {
            val attempt = coreStopRecoveries.incrementAndGet()
            if (attempt <= MAX_CORE_STOP_RECOVERIES) {
                val delayMs = min(1_000L * attempt, 5_000L)
                serviceScope.launch {
                    delay(delayMs)
                    if (!desireStore.read().wanted || stopInProgress.get()) return@launch
                    requestRestart(
                        profileId = profileId,
                        reason = "Автовосстановление VPN",
                        startId = 0,
                        noCacheLookup = false,
                        updaterRouting = desire.updaterRouting,
                    )
                }
                return
            }
        }
        requestStop(
            startId = 0,
            errorMessage = "sing-box остановил VPN-сервис.",
            trigger = "core_stop",
            clearDesire = false,
        )
    }

    private fun showForeground(state: ForegroundNotificationState) {
        updateForegroundNotification(state.text)
    }

    private fun updateForegroundNotification(contentText: String) {
        val openIntent = PendingIntent.getActivity(
            this,
            1,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getService(
            this,
            2,
            stopIntent(this),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val serversIntent = PendingIntent.getActivity(
            this,
            3,
            Intent(this, MainActivity::class.java)
                .putExtra(MainActivity.SHORTCUT_EXTRA, "servers"),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val reconnectIntent = PendingIntent.getActivity(
            this,
            4,
            Intent(this, MainActivity::class.java)
                .putExtra(MainActivity.SHORTCUT_EXTRA, "connect"),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn_notification)
            .setContentTitle("QuantumVPN")
            .setContentText(contentText)
            .setStyle(NotificationCompat.BigTextStyle().bigText(contentText))
            .setContentIntent(openIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .addAction(0, "Открыть", openIntent)
            .addAction(0, "Серверы", serversIntent)
            .addAction(0, "Остановить", stopIntent)
        if (controller.state.value !is VpnConnectionState.Connected &&
            controller.state.value !is VpnConnectionState.Starting
        ) {
            builder.addAction(0, "Подключить", reconnectIntent)
        }
        val notification = builder.build()
        val serviceType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, serviceType)
        foregroundActive.set(true)
    }

    private fun updateTrafficNotification(downloadDelta: Long, uploadDelta: Long) {
        if (activeSession == null || !foregroundActive.get()) return
        acquireWakeLock()
        val stats = container.vpnController.sessionStats.value
        val place = stats.exitLocation?.displayLabel
            ?: stats.externalIp
            ?: "VPN"
        if (muteNotificationTrafficDetail) {
            updateForegroundNotification("Подключено · $place")
            return
        }
        val down = formatNotificationRate(downloadDelta)
        val up = formatNotificationRate(uploadDelta)
        val ping = stats.pingMillis?.let { " · ${it} ms" }.orEmpty()
        val duration = stats.connectedAtEpochMillis?.let { started ->
            val sec = ((System.currentTimeMillis() - started).coerceAtLeast(0L) / 1000L)
            val mm = sec / 60
            val ss = sec % 60
            " · ${mm}м ${ss}с"
        }.orEmpty()
        updateForegroundNotification("$place$ping$duration\n↓ $down  ·  ↑ $up")
    }

    private fun cancelScheduledNetworkRestart() {
        synchronized(restartScheduleLock) {
            networkRestartJob?.cancel()
            networkRestartJob = null
        }
    }

    private fun trackLifecycleJob(job: Job) {
        val previous = synchronized(lifecycleJobLock) {
            val old = lifecycleJob
            lifecycleJob = job
            old
        }
        previous?.cancel()
        job.invokeOnCompletion {
            synchronized(lifecycleJobLock) {
                if (lifecycleJob === job) lifecycleJob = null
            }
        }
    }

    private fun cancelLifecycleJob() {
        synchronized(lifecycleJobLock) {
            lifecycleJob?.cancel(CancellationException("VPN lifecycle отменён."))
            lifecycleJob = null
        }
    }

    private fun registerPendingSession(session: ActiveSession, generation: Long): Boolean =
        synchronized(sessionStateLock) {
            if (generation != controller.currentGeneration()) {
                false
            } else {
                check(pendingSession == null) { "Параллельный запуск VPN запрещён." }
                pendingSession = session
                true
            }
        }

    private fun activatePendingSession(session: ActiveSession, generation: Long): Boolean =
        synchronized(sessionStateLock) {
            if (
                generation != controller.currentGeneration() ||
                pendingSession !== session
            ) {
                false
            } else {
                pendingSession = null
                activeSession = session
                true
            }
        }

    private fun discardSession(session: ActiveSession) {
        synchronized(sessionStateLock) {
            if (pendingSession === session) pendingSession = null
            if (activeSession === session) activeSession = null
        }
    }

    private fun detachSessions(): List<ActiveSession> = synchronized(sessionStateLock) {
        val sessions = listOfNotNull(activeSession, pendingSession).distinct()
        activeSession = null
        pendingSession = null
        sessions
    }

    private fun finishForeground() {
        if (!foregroundActive.compareAndSet(true, false)) return
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
    }

    private fun createNotificationChannel() {
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "VPN",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Состояние VPN и действие остановки"
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            },
        )
    }

    private fun safeError(error: Throwable): VpnConnectionState.Error {
        val causes = generateSequence(error) { it.cause }.toList()
        val coded = causes.filterIsInstance<CodedFailure>().firstOrNull()
        val raw = coded?.userMessage ?: causes
            .mapNotNull { it.message }
            .firstOrNull(String::isNotBlank)
            ?: "Не удалось запустить VPN."
        val message = humanizeVpnFailure(raw)
            .let(SecretRedactor::redactInline)
            .replace(NEW_LINES, " ")
            .trim()
            .take(360)
        val technicalDetail = (coded?.technicalDetail ?: raw)
            .let(SecretRedactor::redactInline)
            .replace(NEW_LINES, " ")
            .trim()
            .take(240)
        return VpnConnectionState.Error(
            message = message,
            code = coded?.failureCode.orEmpty(),
            technicalDetail = technicalDetail,
        )
    }

    private fun humanizeVpnFailure(raw: String): String {
        val text = raw.lowercase()
        return when {
            "configure tun" in text || "tun-in" in text || "tun interface" in text ->
                "Не удалось создать VPN-туннель. Отключите другой VPN / Always-on и разрешите QuantumVPN."
            "permission" in text || "not prepared" in text ->
                "Нужно разрешение VPN в Android. Подтвердите запрос системы."
            "revoke" in text ->
                "Разрешение VPN отозвано. Включите VPN снова."
            else -> raw.take(180)
        }
    }

    private class ActiveSession(
        val profileId: String,
        val profileName: String,
        val generation: Long,
        val networkMonitor: DefaultNetworkMonitor,
        val networkPolicyKey: UnderlyingPolicyKey,
        val outboundDescriptions: Map<String, OutboundDescription>,
        selectorGroups: List<SelectorGroup>,
        val updaterRouting: Boolean,
        private val controller: VpnController,
        private val onTrafficRate: (downloadBytesPerSecond: Long, uploadBytesPerSecond: Long) -> Unit,
    ) : AutoCloseable {
        private val closing = AtomicBoolean(false)
        private val tunCloseStarted = AtomicBoolean(false)
        private val cleanupStarted = AtomicBoolean(false)
        private val cleanupComplete = CountDownLatch(1)
        private val libboxStarted = AtomicBoolean(false)
        private val resourceLock = Any()
        @Volatile private var platform: AndroidPlatformAdapter? = null
        @Volatile private var server: CommandServer? = null
        @Volatile private var client: CommandClient? = null
        private var networkObserver: AutoCloseable? = null
        private var statusObserver: Job? = null
        private var diagnosticsObserver: Job? = null
        private var identityJob: Job? = null
        private var trafficWatchdogJob: Job? = null
        private var statusClient: CommandClient? = null
        private var statusClientCounted = false
        private var logClient: CommandClient? = null
        private var logClientCounted = false
        @Volatile private var stopDiagnosticGeneration = Long.MIN_VALUE
        private val pingTargetResolver = ServerPingTargetResolver(outboundDescriptions, selectorGroups)

        init {
            VpnRuntimeMetrics.sessionOpened()
        }

        fun selectedPingTarget(groups: List<RuntimeSelectorGroup>): ServerPingTarget? =
            pingTargetResolver.selected(groups)

        fun groupPingTargets(
            groupTag: String,
            groups: List<RuntimeSelectorGroup>,
        ): List<ServerPingTarget> = pingTargetResolver.group(groupTag, groups)

        fun attachPlatform(candidate: AndroidPlatformAdapter) {
            val accepted = synchronized(resourceLock) {
                if (closing.get()) false else {
                    check(platform == null)
                    platform = candidate
                    true
                }
            }
            if (!accepted) {
                candidate.close()
                throw CancellationException("Запуск отменён до создания TUN.")
            }
        }

        fun platform(): AndroidPlatformAdapter =
            platform ?: throw CancellationException("Android VPN adapter уже закрыт.")

        fun attachServer(candidate: CommandServer) {
            val accepted = synchronized(resourceLock) {
                if (closing.get()) false else {
                    check(server == null)
                    server = candidate
                    true
                }
            }
            if (!accepted) {
                runCatching { candidate.close() }
                throw CancellationException("Запуск command server отменён.")
            }
        }

        fun attachClient(candidate: CommandClient) {
            val accepted = synchronized(resourceLock) {
                if (closing.get()) false else {
                    check(client == null)
                    client = candidate
                    true
                }
            }
            if (!accepted) {
                runCatching { candidate.disconnect() }
                throw CancellationException("Подключение command client отменено.")
            }
        }

        fun client(): CommandClient? = client

        fun attachNetworkObserver(candidate: AutoCloseable) {
            val accepted = synchronized(resourceLock) {
                if (closing.get()) false else {
                    check(networkObserver == null)
                    networkObserver = candidate
                    true
                }
            }
            if (!accepted) runCatching { candidate.close() }
        }

        fun attachStatusObserver(candidate: Job) = attachJob(candidate) {
            check(statusObserver == null)
            statusObserver = candidate
        }

        fun attachDiagnosticsObserver(candidate: Job) = attachJob(candidate) {
            check(diagnosticsObserver == null)
            diagnosticsObserver = candidate
        }

        fun replaceIdentityJob(candidate: Job) {
            val previous = synchronized(resourceLock) {
                if (closing.get()) {
                    null
                } else {
                    identityJob.also { identityJob = candidate }
                }
            }
            previous?.cancel()
            if (closing.get()) candidate.cancel()
        }

        fun replaceTrafficWatchdogJob(candidate: Job) {
            val previous = synchronized(resourceLock) {
                if (closing.get()) {
                    null
                } else {
                    trafficWatchdogJob.also { trafficWatchdogJob = candidate }
                }
            }
            previous?.cancel()
            if (closing.get()) candidate.cancel()
        }

        private inline fun attachJob(candidate: Job, crossinline attach: () -> Unit) {
            val accepted = synchronized(resourceLock) {
                if (closing.get()) false else {
                    attach()
                    true
                }
            }
            if (!accepted) candidate.cancel()
        }

        fun markLibboxStarted() {
            if (!closing.get() && libboxStarted.compareAndSet(false, true)) {
                VpnRuntimeMetrics.libboxOpened()
            }
        }

        fun enableStopDiagnostics(generation: Long) {
            stopDiagnosticGeneration = generation
        }

        fun closeTun() {
            closing.set(true)
            if (!tunCloseStarted.compareAndSet(false, true)) return
            timedStopStage("close_tun", "Закрытие Android TUN") {
                val current = synchronized(resourceLock) {
                    platform.also { platform = null }
                }
                current?.close()
            }
        }

        @Synchronized
        fun openStatusClient(controller: VpnController) {
            if (closing.get() || statusClient != null) return
            val candidate = Libbox.newCommandClient(
                StatusClientHandler(controller, generation, onTrafficRate),
                CommandClientOptions().apply {
                    addCommand(Libbox.CommandStatus)
                    addCommand(Libbox.CommandConnections)
                    statusInterval = STATUS_INTERVAL_NANOS
                },
            )
            try {
                candidate.connect()
                if (closing.get()) {
                    runCatching { candidate.disconnect() }
                    return
                }
                statusClient = candidate
                statusClientCounted = true
                VpnRuntimeMetrics.statusClientOpened()
                controller.publishStatusStream(generation, true)
            } catch (_: Throwable) {
                runCatching { candidate.disconnect() }
                controller.publishStatusStream(generation, false)
            }
        }

        @Synchronized
        fun closeStatusClient(controller: VpnController) {
            val current = statusClient
            statusClient = null
            runCatching { current?.disconnect() }
            if (statusClientCounted) {
                statusClientCounted = false
                VpnRuntimeMetrics.statusClientClosed()
            }
            controller.publishStatusStream(generation, false)
        }

        @Synchronized
        fun openLogClient(controller: VpnController) {
            if (closing.get() || logClient != null) return
            val candidate = Libbox.newCommandClient(
                DiagnosticLogClientHandler(controller, generation),
                CommandClientOptions().apply { addCommand(Libbox.CommandLog) },
            )
            try {
                candidate.connect()
                if (closing.get()) {
                    runCatching { candidate.disconnect() }
                    return
                }
                logClient = candidate
                logClientCounted = true
                VpnRuntimeMetrics.logClientOpened()
                controller.publishDiagnosticLogStream(generation, true)
            } catch (_: Throwable) {
                runCatching { candidate.disconnect() }
                controller.publishDiagnosticLogStream(generation, false)
            }
        }

        @Synchronized
        fun closeLogClient(controller: VpnController) {
            val current = logClient
            logClient = null
            runCatching { current?.disconnect() }
            if (logClientCounted) {
                logClientCounted = false
                VpnRuntimeMetrics.logClientClosed()
            }
            controller.publishDiagnosticLogStream(generation, false)
        }

        override fun close() {
            closing.set(true)
            if (!cleanupStarted.compareAndSet(false, true)) {
                cleanupComplete.await()
                return
            }
            try {
                closeTun()
                timedStopStage("close_observers", "Остановка callback и фоновых задач") {
                    val resources = synchronized(resourceLock) {
                        listOfNotNull(statusObserver, diagnosticsObserver, identityJob, trafficWatchdogJob).also {
                            statusObserver = null
                            diagnosticsObserver = null
                            identityJob = null
                            trafficWatchdogJob = null
                        }
                    }
                    resources.forEach(Job::cancel)
                }
                timedStopStage("close_clients", "Отключение клиентов libbox") {
                    closeStatusClient(controller)
                    closeLogClient(controller)
                    val current = synchronized(resourceLock) {
                        client.also { client = null }
                    }
                    runCatching { current?.disconnect() }
                    val observer = synchronized(resourceLock) {
                        networkObserver.also { networkObserver = null }
                    }
                    runCatching { observer?.close() }
                }
                timedStopStage("close_libbox_service", "Остановка сервиса libbox") {
                    runCatching { server?.closeService() }.getOrThrow()
                }
                if (libboxStarted.compareAndSet(true, false)) VpnRuntimeMetrics.libboxClosed()
                timedStopStage("close_command_server", "Закрытие command server") {
                    val current = synchronized(resourceLock) {
                        server.also { server = null }
                    }
                    runCatching { current?.close() }.getOrThrow()
                }
                timedStopStage("close_network", "Закрытие мониторинга сети") {
                    networkMonitor.close()
                }
            } finally {
                VpnRuntimeMetrics.sessionClosed()
                cleanupComplete.countDown()
            }
        }

        private inline fun timedStopStage(
            key: String,
            label: String,
            action: () -> Unit,
        ) {
            val diagnosticGeneration = stopDiagnosticGeneration
            if (diagnosticGeneration != Long.MIN_VALUE) {
                controller.startStopDiagnosticStage(diagnosticGeneration, key, label)
            }
            val error = runCatching(action).exceptionOrNull()
            if (diagnosticGeneration != Long.MIN_VALUE) {
                controller.finishStopDiagnosticStage(diagnosticGeneration, key, error)
            }
        }
    }

    private class RuntimeSwitchException(cause: Throwable) : Exception(cause)

    private class ConnectionStartupTimeoutException : Exception(
        "Подключение не завершилось за ${CONNECTION_START_TIMEOUT_MILLIS / 1_000} секунд. " +
            "VPN полностью остановлен; повторите после стабилизации сети.",
    ), CodedFailure {
        override val failureCode = "VPN-120"
        override val userMessage = checkNotNull(message)
        override val technicalDetail = "timeout_ms=$CONNECTION_START_TIMEOUT_MILLIS"
    }

    private class ServerHandler(
        private val service: QuantumVpnService,
    ) : CommandServerHandler {
        override fun getSystemProxyStatus(): SystemProxyStatus = SystemProxyStatus().apply {
            available = false
            enabled = false
        }

        override fun serviceReload() = throw UnsupportedOperationException("Reload выполняет Android-сервис.")
        override fun serviceStop() = service.requestStopFromCore()
        override fun setSystemProxyEnabled(enabled: Boolean) {
            check(!enabled) { "Системный proxy не поддерживается." }
        }
        override fun writeDebugMessage(message: String) = Unit
    }

    private abstract class BaseClientHandler : CommandClientHandler {
        override fun connected() = Unit
        override fun disconnected(message: String) = Unit
        override fun setDefaultLogLevel(level: Int) = Unit
        override fun clearLogs() = Unit
        override fun writeLogs(messageList: LogIterator) = Unit
        override fun writeStatus(message: StatusMessage) = Unit
        override fun initializeClashMode(modeList: StringIterator, currentMode: String) = Unit
        override fun updateClashMode(newMode: String) = Unit
        override fun writeConnectionEvents(events: ConnectionEvents) = Unit
        override fun writeGroups(message: OutboundGroupIterator) = Unit
    }

    private class StatusClientHandler(
        private val controller: VpnController,
        private val generation: Long,
        private val onTrafficRate: (downloadBytesPerSecond: Long, uploadBytesPerSecond: Long) -> Unit,
    ) : BaseClientHandler() {
        override fun writeStatus(message: StatusMessage) {
            if (generation != controller.currentGeneration() || !message.trafficAvailable) return
            VpnRuntimeMetrics.updateTraffic(message.uplinkTotal, message.downlinkTotal)
            controller.publishTraffic(
                generation = generation,
                uploadDelta = message.uplink,
                downloadDelta = message.downlink,
                uploadTotal = message.uplinkTotal,
                downloadTotal = message.downlinkTotal,
            )
            onTrafficRate(message.downlink, message.uplink)
        }

        override fun writeConnectionEvents(events: ConnectionEvents) {
            if (generation != controller.currentGeneration()) return
            val iterator = events.iterator()
            while (iterator.hasNext()) {
                val event = iterator.next()
                val connection = event.connection ?: continue
                val outbound = connection.outbound.orEmpty().lowercase()
                val outboundType = connection.outboundType.orEmpty().lowercase()
                val rule = connection.rule.orEmpty().lowercase()
                val blocked = outboundType == "block" ||
                    outbound == "block" ||
                    rule.contains("reject") ||
                    rule.contains("zapret-adblock") ||
                    rule.contains("dns-block-ads")
                if (blocked) {
                    controller.recordAdBlockHit(generation)
                }
            }
        }
    }

    private class DiagnosticLogClientHandler(
        private val controller: VpnController,
        private val generation: Long,
    ) : BaseClientHandler() {
        override fun disconnected(message: String) {
            controller.publishDiagnosticLogStream(generation, false)
        }

        override fun clearLogs() {
            controller.clearCoreDiagnosticLogs(generation)
        }

        override fun writeLogs(messageList: LogIterator) {
            val collector = CoreDiagnosticBatchCollector()
            while (messageList.hasNext()) {
                val entry = messageList.next()
                collector.add(entry.level, entry.message)
            }
            val batch = collector.result()
            controller.publishCoreDiagnosticLogs(generation, batch.entries, batch.droppedLines)
        }
    }

    private class GroupClientHandler(
        private val controller: VpnController,
        private val generation: Long,
        private val descriptions: Map<String, OutboundDescription>,
    ) : BaseClientHandler() {

        override fun writeGroups(message: OutboundGroupIterator) {
            val groups = buildList {
                while (message.hasNext()) {
                    val group = message.next()
                    val items = buildList {
                        val iterator = group.items
                        while (iterator.hasNext()) {
                            val item = iterator.next()
                            val description = descriptions[item.tag]
                            add(
                                RuntimeOutboundItem(
                                    tag = item.tag,
                                    type = item.type.ifBlank { description?.type ?: "unknown" },
                                    endpoint = description?.endpoint,
                                    pingMillis = null,
                                    pingMeasuredAtEpochSeconds = null,
                                ),
                            )
                        }
                    }
                    add(
                        RuntimeSelectorGroup(
                            tag = group.tag,
                            type = group.type,
                            selected = group.selected,
                            selectable = group.selectable,
                            items = items,
                        ),
                    )
                }
            }
            controller.publishGroups(generation, groups)
        }
    }

    private enum class ForegroundNotificationState(val text: String) {
        Preparing("Подготовка VPN"),
        ValidatingProfile("Проверка профиля"),
        CheckingNetwork("Проверка сети Android"),
        ValidatingCore("Проверка sing-box"),
        CreatingTun("Создание TUN"),
        CheckingHealth("Проверка DNS и HTTPS"),
        Connected("Подключено"),
        Restarting("Перезапуск VPN"),
        Stopping("Отключение"),
    }

    companion object {
        private const val STATUS_INTERVAL_NANOS = 1_000_000_000L
        private const val GROUP_PING_CONCURRENCY = 4
        private const val ACTION_START = "com.quantumvpn.vpn.START"
        private const val ACTION_STOP = "com.quantumvpn.vpn.STOP"
        private const val ACTION_SELECT = "com.quantumvpn.vpn.SELECT"
        private const val ACTION_RESTART = "com.quantumvpn.vpn.RESTART"
        private const val ACTION_CLEAR_DNS_CACHE = "com.quantumvpn.vpn.CLEAR_DNS_CACHE"
        private const val ACTION_PING = "com.quantumvpn.vpn.PING"
        private const val ACTION_PING_GROUP = "com.quantumvpn.vpn.PING_GROUP"
        private const val EXTRA_PROFILE_ID = "profile_id"
        private const val EXTRA_GROUP_TAG = "group_tag"
        private const val EXTRA_OUTBOUND_TAG = "outbound_tag"
        private const val EXTRA_REASON = "reason"
        private const val EXTRA_UPDATER_ROUTING = "updater_routing"
        private const val NOTIFICATION_CHANNEL_ID = "vpn"
        private const val NOTIFICATION_ID = 2001
        private const val NETWORK_RESTART_DEBOUNCE_MILLIS = 750L
        private const val CONNECTION_START_TIMEOUT_MILLIS = 45_000L
        private const val DEFERRED_HEALTH_TIMEOUT_MILLIS = 2_500L
        private const val MAX_CORE_STOP_RECOVERIES = 5
        private val NEW_LINES = Regex("[\\r\\n\\t]+")

        private fun formatNotificationRate(bytesPerSecond: Long): String {
            val safe = bytesPerSecond.coerceAtLeast(0)
            return when {
                safe < 1024 -> "$safe Б/с"
                safe < 1024 * 1024 -> "%.1f КБ/с".format(java.util.Locale.US, safe / 1024.0)
                else -> "%.1f МБ/с".format(java.util.Locale.US, safe / (1024.0 * 1024.0))
            }
        }

        fun startIntent(
            context: Context,
            profileId: String,
            updaterRouting: Boolean = false,
        ): Intent =
            Intent(context, QuantumVpnService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_PROFILE_ID, profileId)
                .putExtra(EXTRA_UPDATER_ROUTING, updaterRouting)

        fun stopIntent(context: Context): Intent =
            Intent(context, QuantumVpnService::class.java).setAction(ACTION_STOP)

        fun selectIntent(
            context: Context,
            profileId: String,
            groupTag: String,
            outboundTag: String,
        ): Intent = Intent(context, QuantumVpnService::class.java)
            .setAction(ACTION_SELECT)
            .putExtra(EXTRA_PROFILE_ID, profileId)
            .putExtra(EXTRA_GROUP_TAG, groupTag)
            .putExtra(EXTRA_OUTBOUND_TAG, outboundTag)

        fun restartIntent(
            context: Context,
            profileId: String,
            reason: String,
            updaterRouting: Boolean? = null,
        ): Intent =
            Intent(context, QuantumVpnService::class.java)
                .setAction(ACTION_RESTART)
                .putExtra(EXTRA_PROFILE_ID, profileId)
                .putExtra(EXTRA_REASON, reason)
                .apply {
                    updaterRouting?.let { putExtra(EXTRA_UPDATER_ROUTING, it) }
                }

        fun clearDnsCacheIntent(context: Context): Intent =
            Intent(context, QuantumVpnService::class.java).setAction(ACTION_CLEAR_DNS_CACHE)

        fun pingIntent(context: Context): Intent =
            Intent(context, QuantumVpnService::class.java).setAction(ACTION_PING)

        fun pingGroupIntent(context: Context, profileId: String, groupTag: String): Intent =
            Intent(context, QuantumVpnService::class.java)
                .setAction(ACTION_PING_GROUP)
                .putExtra(EXTRA_PROFILE_ID, profileId)
                .putExtra(EXTRA_GROUP_TAG, groupTag)
    }
}
