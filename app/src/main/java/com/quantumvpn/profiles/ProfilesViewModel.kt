package com.quantumvpn.profiles

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.quantumvpn.config.ConfigAnalyzer
import com.quantumvpn.config.DnsMode
import com.quantumvpn.config.ConfigValidationResult
import com.quantumvpn.config.ConfigValidator
import com.quantumvpn.config.JsonConfig
import com.quantumvpn.config.SelectorGroup
import com.quantumvpn.routing.HappRoutingCompiler
import com.quantumvpn.routing.HappRoutingImport
import com.quantumvpn.routing.HappRoutingProfileStore
import com.quantumvpn.routing.RoutingConfigEditor
import com.quantumvpn.routing.RoutingPreset
import com.quantumvpn.routing.RuleSetAssetManager
import com.quantumvpn.importer.AndroidImportReader
import com.quantumvpn.importer.HttpSubscriptionFetcher
import com.quantumvpn.importer.ImportCandidate
import com.quantumvpn.importer.ImportException
import com.quantumvpn.importer.ImportParser
import com.quantumvpn.importer.ImportedConfigActivityScanner
import com.quantumvpn.importer.SubscriptionFetcher
import com.quantumvpn.importer.SubscriptionQuotaStore
import com.quantumvpn.importer.SubscriptionSourceStore
import com.quantumvpn.importer.SubscriptionUserInfo
import com.quantumvpn.diagnostics.ConnectDurationStore
import com.quantumvpn.diagnostics.DisconnectReasonStore
import com.quantumvpn.diagnostics.DnsLatencyProbe
import com.quantumvpn.diagnostics.EventJournalStore
import com.quantumvpn.diagnostics.SecretRedactor
import com.quantumvpn.diagnostics.SessionTrafficHistoryStore
import com.quantumvpn.diagnostics.ReliabilityReportStore
import com.quantumvpn.diagnostics.SettingsAuditStore
import com.quantumvpn.diagnostics.SpeedTestHistoryStore
import com.quantumvpn.hardening.TunMtuMode
import com.quantumvpn.policy.ClientFeatureGate
import com.quantumvpn.ui.AccentColor
import com.quantumvpn.ui.ConnectionExperienceMode
import com.quantumvpn.ui.HomeLayoutMode
import com.quantumvpn.ui.HomeVisualTheme
import com.quantumvpn.ui.PowerMode
import com.quantumvpn.ui.ServerMode
import com.quantumvpn.ui.ThemeMode
import com.quantumvpn.ui.UiSettings
import com.quantumvpn.ui.UiSettingsStore
import com.quantumvpn.ui.bypassPreset
import com.quantumvpn.ui.labelRu
import com.quantumvpn.ui.routingPresetOrNull
import com.quantumvpn.updates.UpdateChannel
import com.quantumvpn.vpn.SpeedTestProbe
import com.quantumvpn.vpn.VpnController
import com.quantumvpn.vpn.BootstrapCache
import com.quantumvpn.vpn.VpnConnectionState
import com.quantumvpn.vpn.ExitLocationResolver
import com.quantumvpn.importer.SubscriptionSourceHealthStore
import com.quantumvpn.vpn.DeadServerQuarantineStore
import com.quantumvpn.vpn.ServerReliabilityStore
import com.quantumvpn.vpn.FavoriteServersStore
import com.quantumvpn.vpn.PinnedServersStore
import com.quantumvpn.vpn.RecentServer
import com.quantumvpn.vpn.RecentServersStore
import com.quantumvpn.vpn.RuntimeOutboundItem
import com.quantumvpn.vpn.RuntimeSelectorGroup
import com.quantumvpn.vpn.ServerNotesStore
import com.quantumvpn.vpn.SessionSwitchHistoryStore
import com.quantumvpn.vpn.forServerUi
import com.quantumvpn.vpn.primaryGroup
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class ProfileEditorState(
    val profileId: String,
    val profileName: String,
    val originalText: String,
    val text: String,
    val search: String = "",
    val validationMessage: String? = null,
    val validationSuccessful: Boolean = false,
    val selectors: List<SelectorGroup> = emptyList(),
    val serverTags: List<String> = emptyList(),
    val hasBackup: Boolean = false,
) {
    val hasUnsavedChanges: Boolean get() = text != originalText
    val searchMatches: Int
        get() {
            if (search.isBlank()) return 0
            var count = 0
            var start = 0
            while (start <= text.length - search.length) {
                val found = text.indexOf(search, startIndex = start, ignoreCase = true)
                if (found < 0) break
                count++
                start = found + 1
            }
            return count
        }
}

data class ProfilesUiState(
    val profiles: List<ProfileMetadata> = emptyList(),
    val settings: UiSettings = UiSettings(),
    val editor: ProfileEditorState? = null,
    val busy: Boolean = false,
    val message: String? = null,
    val importPreview: ImportPreviewState? = null,
    val importCompletion: ImportCompletion? = null,
    val refreshableProfileIds: Set<String> = emptySet(),
    /** Selector groups of the active profile for Happ-style server picker on Home. */
    val homeSelectorGroups: List<RuntimeSelectorGroup> = emptyList(),
    val subscriptionQuota: SubscriptionUserInfo? = null,
    val initialized: Boolean = false,
    val undoMessage: String? = null,
    val subscriptionDiff: SubscriptionDiffResult? = null,
)

data class ImportCompletion(
    val profileId: String,
    val profileName: String,
)

data class ImportPreviewState(
    val suggestedName: String,
    val sourceDescription: String,
    val serverCount: Int,
    val serverLabels: List<String>,
    val activityWarning: String?,
    val appendTargets: List<ProfileMetadata>,
    val refreshProfileId: String? = null,
    val refreshProfileName: String? = null,
    val activeRefresh: Boolean = false,
    val selectionChanged: Boolean = false,
    internal val candidate: ImportCandidate,
    internal val preparedJson: String,
    internal val sourceUrl: String? = null,
    internal val routing: HappRoutingImport = HappRoutingImport.None,
) {
    val isSingleManaged: Boolean
        get() = candidate is ImportCandidate.Managed && candidate.servers.size == 1
    val isRefresh: Boolean get() = refreshProfileId != null
}

class ProfilesViewModel(
    private val store: ProfileStore,
    private val settingsStore: UiSettingsStore,
    private val validator: ConfigValidator,
    private val importReader: AndroidImportReader,
    private val subscriptionFetcher: SubscriptionFetcher,
    private val subscriptionSourceStore: SubscriptionSourceStore,
    private val vpnController: VpnController,
    private val bootstrapCache: BootstrapCache,
    private val ruleSetAssets: RuleSetAssetManager,
    private val happRoutingStore: HappRoutingProfileStore,
    private val olcrtcEngineStore: com.quantumvpn.olcrtc.OlcrtcEngineStore,
    private val recentServersStore: RecentServersStore,
    private val favoriteServersStore: FavoriteServersStore,
    private val pinnedServersStore: PinnedServersStore,
    private val profileBackupImporter: ProfileBackupImporter,
    private val eventJournal: EventJournalStore,
    private val sessionSwitchHistory: SessionSwitchHistoryStore,
    private val subscriptionQuotaStore: SubscriptionQuotaStore,
    private val disconnectReasonStore: DisconnectReasonStore,
    private val speedTestHistoryStore: SpeedTestHistoryStore,
    private val connectDurationStore: ConnectDurationStore,
    private val serverNotesStore: ServerNotesStore,
    private val sessionTrafficHistoryStore: SessionTrafficHistoryStore,
    private val settingsAuditStore: SettingsAuditStore,
    private val reliabilityReportStore: ReliabilityReportStore,
    private val deadServerQuarantineStore: DeadServerQuarantineStore,
    private val serverReliabilityStore: ServerReliabilityStore,
    private val lastKnownGoodStore: LastKnownGoodStore,
    private val subscriptionSourceHealthStore: SubscriptionSourceHealthStore,
    private val importClipboardClear: () -> Unit,
) : ViewModel() {
    private var pendingUndoAction: (suspend () -> Unit)? = null
    private val mutableState = MutableStateFlow(ProfilesUiState())
    val state: StateFlow<ProfilesUiState> = mutableState.asStateFlow()
    val recentServers: StateFlow<List<RecentServer>> = recentServersStore.recents
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
    val favoriteKeys: StateFlow<Set<String>> = favoriteServersStore.favorites
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptySet())
    val pinnedKeys: StateFlow<List<String>> = pinnedServersStore.pins
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
    val quarantinedServerKeys: StateFlow<Set<String>> = deadServerQuarantineStore.entries
        .map { map ->
            val now = System.currentTimeMillis()
            map.filterValues { it.quarantineUntilEpochMillis > now }.keys
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptySet())
    val reliabilityScores = serverReliabilityStore.entries
        .map { map -> map.mapValues { it.value.score } }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyMap())
    /** Full per-server reliability entries (successes/failures) for the ranking screen. */
    val reliabilityEntries = serverReliabilityStore.entries
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyMap())
    val reliabilitySummary = reliabilityReportStore.summary
        .stateIn(
            viewModelScope,
            SharingStarted.WhileSubscribed(5_000),
            com.quantumvpn.diagnostics.ReliabilitySummary(
                weekLabel = ReliabilityReportStore.currentWeekKey(),
                connectSuccess = 0,
                connectFail = 0,
                disconnects = 0,
                totalSessionSec = 0,
                uptimePercent = 100,
            ),
        )
    val journalEvents = eventJournal.events
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
    val switchHistory = sessionSwitchHistory.events
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
    val lastDisconnectReason = disconnectReasonStore.lastReason
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)
    val disconnectHistory = disconnectReasonStore.history
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
    val serverNotes = serverNotesStore.notes
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyMap())
    val speedTestHistory = speedTestHistoryStore.records
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
    val connectEtaMillis = connectDurationStore.samples
        .map { samples ->
            val sorted = samples.sorted()
            if (sorted.isEmpty()) null else sorted[sorted.size / 2]
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)
    val connectDurationSamples = connectDurationStore.samples
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
    val sessionTrafficHistory = sessionTrafficHistoryStore.records
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
    val settingsAuditEvents = settingsAuditStore.events
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    fun recordConnectDuration(durationMillis: Long) = operation(markBusy = false) {
        connectDurationStore.record(durationMillis)
    }

    fun noteDisconnectReason(reason: String) = operation(markBusy = false) {
        disconnectReasonStore.set(reason)
        eventJournal.append("disconnect", reason)
        reliabilityReportStore.recordDisconnect()
    }

    fun recordConnectSuccess() = operation(markBusy = false) {
        reliabilityReportStore.recordConnectSuccess()
        val profileId = mutableState.value.settings.activeProfileId ?: return@operation
        lastKnownGoodStore.resetFails(profileId)
        runCatching {
            lastKnownGoodStore.pin(profileId, store.read(profileId).json)
        }
    }

    fun recordConnectFail() = operation(markBusy = false) {
        reliabilityReportStore.recordConnectFail()
        val profileId = mutableState.value.settings.activeProfileId ?: return@operation
        val fails = lastKnownGoodStore.recordConnectFail(profileId)
        if (fails >= LastKnownGoodStore.ROLLBACK_THRESHOLD) {
            val good = lastKnownGoodStore.snapshot(profileId)
            if (good != null) {
                store.update(profileId, good)
                lastKnownGoodStore.resetFails(profileId)
                showTip("Авто-откат к последней рабочей конфигурации ($fails ошибок).")
                vpnController.restartIfConnected("Откат last-known-good")
            }
        }
    }

    fun recordServerProbeFailure(profileId: String, groupTag: String, outboundTag: String) =
        operation(markBusy = false) {
            val key = DeadServerQuarantineStore.serverKey(profileId, groupTag, outboundTag)
            deadServerQuarantineStore.recordFailure(key)
            serverReliabilityStore.recordFailure(key)
        }

    fun recordServerProbeSuccess(profileId: String, groupTag: String, outboundTag: String) =
        operation(markBusy = false) {
            val key = DeadServerQuarantineStore.serverKey(profileId, groupTag, outboundTag)
            deadServerQuarantineStore.recordSuccess(key)
            serverReliabilityStore.recordSuccess(key)
        }

    fun togglePinnedServer(profileId: String, groupTag: String, outboundTag: String) =
        operation(markBusy = false) {
            val pinned = pinnedServersStore.toggle(profileId, groupTag, outboundTag)
            showTip(if (pinned) "Сервер закреплён (top-3)." else "Закрепление снято.")
        }

    fun markChangelogSeen(version: String) = operation(markBusy = false) {
        settingsStore.setLastSeenChangelogVersion(version)
    }

    fun dismissCoachMarks() = operation(markBusy = false) {
        settingsStore.setCoachMarksDismissed(true)
    }

    fun dismissCoachMark(screen: com.quantumvpn.ui.CoachMarkScreen) = operation(markBusy = false) {
        settingsStore.dismissCoachMark(screen)
    }

    fun setCustomDohUrl(url: String) = operation(markBusy = false) {
        settingsStore.setCustomDohUrl(url)
    }

    fun setCustomDotUrl(url: String) = operation(markBusy = false) {
        settingsStore.setCustomDotUrl(url)
    }

    fun setSkipAutoConnectWhenRoaming(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setSkipAutoConnectWhenRoaming(enabled)
    }

    fun setAutoConnectOnCellular(enabled: Boolean) = operation(markBusy = false) {
        if (!ClientFeatureGate.features().autoConnect) {
            showMessage("Автоподключение отключено оператором.")
            return@operation
        }
        settingsStore.setAutoConnectOnCellular(enabled)
    }

    fun setProtectUnknownWifi(enabled: Boolean) = operation(markBusy = false) {
        if (!ClientFeatureGate.features().autoConnect) {
            showMessage("Автозащита сети отключена оператором.")
            return@operation
        }
        settingsStore.setProtectUnknownWifi(enabled)
    }

    fun setTimeRoutingEnabled(enabled: Boolean) = operation(markBusy = false) {
        if (!ClientFeatureGate.features().vpnSchedule && !ClientFeatureGate.features().routingEditor) {
            showMessage("Расписание / маршруты отключены оператором.")
            return@operation
        }
        settingsStore.setTimeRoutingEnabled(enabled)
    }

    fun dismissTipsCarousel() = operation(markBusy = false) {
        settingsStore.setTipsCarouselDismissed(true)
    }

    fun dismissSubscriptionDiff() = operation(markBusy = false) {
        pendingUndoAction = null
        mutableState.update { it.copy(subscriptionDiff = null, undoMessage = null) }
    }

    fun undoLastAction() = operation {
        pendingUndoAction?.invoke()
        pendingUndoAction = null
        mutableState.update { it.copy(subscriptionDiff = null, undoMessage = null) }
        showMessage("Отменено.")
    }

    fun consumeUndoOffer() {
        pendingUndoAction = null
        mutableState.update { it.copy(undoMessage = null) }
    }

    private fun offerUndo(message: String, undo: suspend () -> Unit) {
        if (mutableState.value.settings.quietMode) return
        pendingUndoAction = undo
        mutableState.update { it.copy(undoMessage = message) }
    }

    fun setBiometricLockEnabled(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setBiometricLockEnabled(enabled)
    }

    fun setRequireUnlockToDisconnect(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setRequireUnlockToDisconnect(enabled)
    }

    fun setRequireUnlockToChangeServer(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setRequireUnlockToChangeServer(enabled)
    }

    fun setHighContrast(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setHighContrast(enabled)
    }

    fun setSafeModeConnect(enabled: Boolean) = operation(markBusy = false) {
        if (!ClientFeatureGate.features().safeMode) {
            showMessage("Safe mode отключён оператором.")
            return@operation
        }
        settingsStore.setSafeModeConnect(enabled)
    }

    fun overrideFailoverCooldown() = operation(markBusy = false) {
        settingsStore.setFailoverCooldownUntil(0L)
        showTip("Cooldown failover сброшен.")
    }

    fun startFailoverCooldown(minutes: Int = 30) = operation(markBusy = false) {
        val until = System.currentTimeMillis() + minutes * 60_000L
        settingsStore.setFailoverCooldownUntil(until)
        eventJournal.append("failover", "Cooldown ${minutes}m")
    }

    fun recordSessionTraffic(
        profileName: String,
        downloadBytes: Long,
        uploadBytes: Long,
        durationSec: Long,
    ) = operation(markBusy = false) {
        sessionTrafficHistoryStore.record(profileName, downloadBytes, uploadBytes, durationSec)
        reliabilityReportStore.addSessionSeconds(durationSec)
    }

    fun clearSessionTrafficHistory() = operation(markBusy = false) {
        sessionTrafficHistoryStore.clear()
    }

    init {
        viewModelScope.launch {
            try {
                val profiles = store.initialize()
                subscriptionSourceStore.retain(profiles.map(ProfileMetadata::id).toSet())
                happRoutingStore.retain(profiles.map(ProfileMetadata::id).toSet())
                subscriptionQuotaStore.retain(profiles.map(ProfileMetadata::id).toSet())
                mutableState.update {
                    it.copy(refreshableProfileIds = subscriptionSourceStore.ids())
                }
                combine(
                    store.profiles,
                    settingsStore.settings,
                    subscriptionQuotaStore.byProfileId,
                ) { profiles, settings, quotas ->
                    Triple(profiles, settings, quotas)
                }.collect { (profiles, settings, quotas) ->
                    val effectiveId = settings.activeProfileId ?: profiles.firstOrNull()?.id
                    val homeGroups = effectiveId?.let { id ->
                        runCatching { homeSelectorGroups(store.read(id).json) }.getOrDefault(emptyList())
                    }.orEmpty()
                    mutableState.update {
                        it.copy(
                            profiles = profiles,
                            settings = settings,
                            homeSelectorGroups = homeGroups,
                            subscriptionQuota = settings.activeProfileId?.let(quotas::get),
                            initialized = true,
                        )
                    }
                    if (settings.activeProfileId != null && profiles.none { it.id == settings.activeProfileId }) {
                        settingsStore.setActiveProfile(null)
                    }
                }
            } catch (error: Exception) {
                showMessage(error.userMessage("Не удалось открыть профили."))
            }
        }
        viewModelScope.launch {
            // Wait until store is ready, then keep subscriptions fresh automatically.
            mutableState.first { it.initialized }
            refreshAllSubscriptionsQuietly(silent = true)
            while (true) {
                kotlinx.coroutines.delay(30 * 60 * 1000L) // каждые 30 мин, пока процесс жив
                if (com.quantumvpn.vpn.SubscriptionRefreshAlarms.pendingRefresh) {
                    com.quantumvpn.vpn.SubscriptionRefreshAlarms.pendingRefresh = false
                }
                refreshAllSubscriptionsQuietly(silent = true)
            }
        }
    }

    /** Silent Happ-style refresh of every saved subscription URL, then restart VPN if needed. */
    fun refreshAllSubscriptionsQuietly(silent: Boolean = false) = operation(markBusy = false) {
        val ids = subscriptionSourceStore.ids().toList()
        if (ids.isEmpty()) return@operation
        var updated = 0
        var failed = 0
        for (profileId in ids) {
            try {
                applySubscriptionRefresh(profileId)
                updated++
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                failed++
            }
        }
        if (updated > 0) {
            ruleSetAssets.ensureInstalled()
            if (!silent) {
                vpnController.restartIfConnected("Подписки и маршруты обновлены")
            }
            if (!mutableState.value.settings.incognitoSession) {
                if (silent) {
                    showMessage("Подписка обновлена")
                } else {
                    showMessage(
                        if (failed == 0) "Подписки обновлены: $updated."
                        else "Подписки обновлены: $updated, ошибок: $failed.",
                    )
                }
            } else if (silent) {
                eventJournal.append("subscription", "Автообновление: $updated ok, $failed err")
            }
        }
    }

    private suspend fun applySubscriptionRefresh(profileId: String): SubscriptionDiffResult? {
        val sourceUrl = subscriptionSourceStore.get(profileId) ?: return null
        val stored = store.read(profileId)
        val oldJson = stored.json
        val payload = fetchSubscriptionPayload(sourceUrl)
        payload.userInfo?.let { subscriptionQuotaStore.put(profileId, it) }
        val parsed = withContext(Dispatchers.Default) {
            ImportParser.parse(
                payload.body,
                ProfileSource.Url,
                stored.metadata.name,
                routingHeader = payload.routingHeader,
            )
        }
        val candidate = when (val c = parsed.candidate) {
            is ImportCandidate.Managed -> c.copy(servers = ServerDeduper.dedupe(c.servers))
            else -> parsed.candidate
        }
        val candidateJson = candidate.toJson()
        val update = when {
            candidate is ImportCandidate.Managed && ManagedProfileEditor.isManaged(stored.json) ->
                ManagedProfileEditor.refreshServers(stored.json, candidate.servers)
            candidate is ImportCandidate.RawJson ->
                ManagedProfileEditor.preserveSelectorDefaults(stored.json, candidateJson)
            else -> ManagedProfileUpdate(candidateJson, selectedTag = "", selectionChanged = false)
        }
        val json = applyRoutingOverlay(profileId, parsed.routing, update.json)
        require(homeSelectorGroups(json).any { it.items.isNotEmpty() }) {
            "Ответ подписки не содержит серверов. Сохранён предыдущий список."
        }
        requireValid(json)
        val diff = SubscriptionDiff.compute(profileId, stored.metadata.name, oldJson, json)
        store.update(profileId, json)
        if (candidate is ImportCandidate.Managed) writeOlcrtcEngines(profileId, candidate.servers)
        return diff.takeIf { it.hasChanges }
    }

    fun importDocument(uri: Uri) = operation {
        val raw = withContext(Dispatchers.IO) { importReader.readDocument(uri) }
        val displayName = withContext(Dispatchers.IO) { importReader.documentDisplayName(uri) }
        val suggestedName = displayName
            ?.substringBeforeLast('.', displayName)
            ?.trim()
            ?.takeIf(String::isNotEmpty)
            ?: "Профиль из файла"
        val sourceDescription = displayName
            ?.let(SecretRedactor::redactInline)
            ?.let { "Системный файл: $it" }
            ?: "Системный файл"
        preview(raw, ProfileSource.File, suggestedName, sourceDescription)
    }

    fun importClipboard() = operation {
        if (!ClientFeatureGate.features().importJson) {
            showMessage("Импорт отключён оператором.")
            return@operation
        }
        val raw = normalizeClipboard(importReader.readClipboardAfterUserAction())
        ImportParser.extractHttpUrl(raw)?.takeIf { ImportParser.looksLikeSubscriptionUrl(it) }?.let { url ->
            importSubscriptionUrl(url)
            maybeClearClipboard()
            return@operation
        }
        preview(raw, ProfileSource.Clipboard, "Профиль из буфера", "Буфер обмена")
        maybeClearClipboard()
    }

    private suspend fun maybeClearClipboard() {
        if (mutableState.value.settings.clearClipboardAfterImport) {
            runCatching { importClipboardClear() }
            eventJournal.append("import", "Буфер очищен после импорта")
        }
    }

    fun importQr(contents: String) = operation {
        val raw = normalizeClipboard(contents)
        ImportParser.extractHttpUrl(raw)?.takeIf { ImportParser.looksLikeSubscriptionUrl(it) }?.let { url ->
            importSubscriptionUrl(url)
            return@operation
        }
        preview(raw, ProfileSource.Qr, "Профиль из QR", "QR-код")
    }

    fun importUrl(url: String) = operation {
        val trimmed = normalizeClipboard(url)
        if (trimmed.isEmpty()) throw ImportException("URL подписки пуст.")
        // Paste of share-links / JSON / WireGuard into the URL field should not be refused.
        if (ImportParser.looksLikeInlineImport(trimmed)) {
            preview(
                raw = trimmed,
                source = ProfileSource.Link,
                suggestedName = "Импорт по ссылке",
                sourceDescription = "Вставленная ссылка / конфиг",
            )
            return@operation
        }
        val http = ImportParser.extractHttpUrl(trimmed) ?: trimmed
        importSubscriptionUrl(http)
    }

    /** Loads the only subscription offered by the application. */
    fun installManagedSubscription() = operation {
        importSubscriptionUrl(
            url = ManagedSubscriptionEndpoint.url,
            suggestedName = ManagedSubscriptionEndpoint.profileName,
            sourceDescription = ManagedSubscriptionEndpoint.sourceDescription,
        )
    }

    private suspend fun importSubscriptionUrl(
        url: String,
        suggestedName: String = "Подписка",
        sourceDescription: String = SecretRedactor.redactInline(url),
    ) {
        val validatedUrl = HttpSubscriptionFetcher.validatedUrl(url)
        val payload = fetchSubscriptionPayload(validatedUrl)
        preview(
            raw = payload.body,
            source = ProfileSource.Url,
            suggestedName = suggestedName,
            sourceDescription = sourceDescription,
            sourceUrl = validatedUrl,
            routingHeader = payload.routingHeader,
        )
    }

    private fun normalizeClipboard(raw: String): String =
        raw.trim()
            .removePrefix("\uFEFF")
            .trim('"', '\'', '«', '»', '`')
            .trim()

    fun refreshSubscription(profileId: String) = operation {
        val sourceUrl = subscriptionSourceStore.get(profileId)
            ?: throw ImportException("Для этого профиля не сохранён URL ручного обновления.")
        val stored = store.read(profileId)
        val payload = fetchSubscriptionPayload(sourceUrl)
        payload.userInfo?.let { subscriptionQuotaStore.put(profileId, it) }
        val parsed = withContext(Dispatchers.Default) {
            ImportParser.parse(
                payload.body,
                ProfileSource.Url,
                stored.metadata.name,
                routingHeader = payload.routingHeader,
            )
        }
        val candidate = parsed.candidate
        val candidateJson = candidate.toJson()
        val update = when {
            candidate is ImportCandidate.Managed && ManagedProfileEditor.isManaged(stored.json) ->
                ManagedProfileEditor.refreshServers(stored.json, candidate.servers)
            candidate is ImportCandidate.RawJson ->
                ManagedProfileEditor.preserveSelectorDefaults(stored.json, candidateJson)
            else -> ManagedProfileUpdate(candidateJson, selectedTag = "", selectionChanged = false)
        }
        val prepared = applyRoutingOverlay(profileId, parsed.routing, update.json)
        requireValid(prepared)
        val currentVpn = vpnController.state.value
        mutableState.update {
            it.copy(
                importPreview = ImportPreviewState(
                    suggestedName = stored.metadata.name,
                    sourceDescription = SecretRedactor.redactInline(sourceUrl),
                    serverCount = candidate.serverCount(),
                    serverLabels = candidate.serverLabels(),
                    activityWarning = importWarnings(prepared),
                    appendTargets = emptyList(),
                    refreshProfileId = profileId,
                    refreshProfileName = stored.metadata.name,
                    activeRefresh = currentVpn is VpnConnectionState.Connected &&
                        currentVpn.profileId == profileId,
                    selectionChanged = update.selectionChanged,
                    candidate = candidate,
                    preparedJson = prepared,
                    sourceUrl = sourceUrl,
                    routing = parsed.routing,
                ),
                message = null,
            )
        }
    }

    fun confirmImport(name: String) = operation {
        val pending = mutableState.value.importPreview
            ?.takeUnless { it.isRefresh }
            ?: throw ImportException("Предпросмотр импорта уже закрыт.")
        val metadata = store.create(name, pending.preparedJson, pending.candidate.source)
        pending.sourceUrl?.let { subscriptionSourceStore.put(metadata.id, it) }
        if (pending.routing !is HappRoutingImport.None) {
            val json = applyRoutingOverlay(metadata.id, pending.routing, store.read(metadata.id).json)
            requireValid(json)
            store.update(metadata.id, json)
        }
        (pending.candidate as? ImportCandidate.Managed)?.let { managed ->
            writeOlcrtcEngines(metadata.id, managed.servers)
        }
        if (mutableState.value.settings.activeProfileId == null) {
            settingsStore.setActiveProfile(metadata.id)
            settingsStore.setDnsMode(
                if (pending.candidate is ImportCandidate.Managed) DnsMode.Automatic else DnsMode.FromJson,
            )
        }
        mutableState.update {
            it.copy(
                importPreview = null,
                importCompletion = ImportCompletion(metadata.id, metadata.name),
                refreshableProfileIds = if (pending.sourceUrl != null) {
                    it.refreshableProfileIds + metadata.id
                } else {
                    it.refreshableProfileIds
                },
            )
        }
        showMessage("Профиль сохранён. Подключение не запускалось.")
    }

    fun confirmAppend(targetProfileId: String) = operation {
        val pending = mutableState.value.importPreview
            ?.takeUnless { it.isRefresh }
            ?: throw ImportException("Предпросмотр импорта уже закрыт.")
        val server = (pending.candidate as? ImportCandidate.Managed)?.servers?.singleOrNull()
            ?: throw ImportException("Добавить можно только одну серверную ссылку.")
        val target = store.read(targetProfileId)
        val update = ManagedProfileEditor.appendServer(target.json, server)
        store.update(targetProfileId, update.json)
        appendOlcrtcEngine(targetProfileId, target.json, server)
        mutableState.update { it.copy(importPreview = null) }
        showMessage("Сервер добавлен в ${target.metadata.name}. Работающий VPN не изменён.")
    }

    fun confirmRefresh(restartConnected: Boolean) = operation {
        val pending = mutableState.value.importPreview
            ?.takeIf { it.isRefresh }
            ?: throw ImportException("Предпросмотр обновления уже закрыт.")
        val profileId = checkNotNull(pending.refreshProfileId)
        if (pending.routing !is HappRoutingImport.None) {
            happRoutingStore.applyImport(profileId, pending.routing)
        }
        store.update(profileId, pending.preparedJson)
        (pending.candidate as? ImportCandidate.Managed)?.let { managed ->
            writeOlcrtcEngines(profileId, managed.servers)
        }
        mutableState.update { it.copy(importPreview = null) }
        val connectedNow = (vpnController.state.value as? VpnConnectionState.Connected)
            ?.profileId == profileId
        if (restartConnected && connectedNow) {
            vpnController.restartIfConnected("Подписка обновлена пользователем")
            showMessage(
                if (pending.selectionChanged) {
                    "Выбранный сервер исчез: выбран первый доступный; VPN контролируемо перезапущен."
                } else {
                    "Подписка сохранена; подтверждён контролируемый перезапуск VPN."
                },
            )
        } else if (restartConnected && pending.activeRefresh) {
            showMessage("Подписка сохранена; VPN уже отключён, перезапуск не требуется.")
        } else if (pending.selectionChanged) {
            showMessage("Выбранный сервер исчез: выбран первый доступный. VPN не перезапущен.")
        } else {
            showMessage("Подписка обновлена. Работающий VPN не изменён.")
        }
    }

    fun dismissImportPreview() {
        mutableState.update { it.copy(importPreview = null) }
    }

    fun consumeImportCompletion() {
        mutableState.update { it.copy(importCompletion = null) }
    }

    fun selectProfile(id: String) = operation {
        require(mutableState.value.profiles.any { it.id == id }) { "Профиль не найден." }
        settingsStore.setActiveProfile(id)
        showMessage("Активный профиль выбран.")
    }

    fun swapToPreviousServer() = operation {
        val recents = recentServers.value
        if (recents.size < 2) {
            showTip("Нет предыдущего сервера.")
            return@operation
        }
        val previous = recents[1]
        val profileId = mutableState.value.settings.activeProfileId
            ?: error("Сначала выберите подписку.")
        val stored = store.read(profileId)
        val updated = ConfigAnalyzer.selectServer(stored.json, previous.groupTag, previous.outboundTag)
        store.update(profileId, updated)
        mutableState.update { it.copy(homeSelectorGroups = homeSelectorGroups(updated)) }
        val location = ExitLocationResolver.fromServerLabel(previous.outboundTag)
        recentServersStore.record(
            RecentServer(
                profileId = profileId,
                groupTag = previous.groupTag,
                outboundTag = previous.outboundTag,
                displayName = previous.outboundTag,
                countryCode = location?.countryCode,
                flagEmoji = location?.flagEmoji,
                usedAtEpochMillis = System.currentTimeMillis(),
            ),
        )
        when (val vpn = vpnController.state.value) {
            is VpnConnectionState.Connected ->
                if (vpn.profileId == profileId) {
                    vpnController.selectOutbound(profileId, previous.groupTag, previous.outboundTag)
                }
            else -> Unit
        }
        showTip("Сервер: ${previous.outboundTag}")
    }

    /**
     * Happ-style server pick on Home: write selector.default into the active profile JSON.
     * When VPN is already up, also switch the live outbound.
     */
    fun selectActiveServer(groupTag: String, outboundTag: String) = operation {
        val profileId = mutableState.value.settings.activeProfileId
            ?: error("Сначала выберите подписку.")
        val stored = store.read(profileId)
        val previousTag = ConfigAnalyzer.outboundGroups(stored.json)
            .firstOrNull { it.tag == groupTag }?.default
        val updated = ConfigAnalyzer.selectServer(stored.json, groupTag, outboundTag)
        store.update(profileId, updated)
        mutableState.update {
            it.copy(homeSelectorGroups = homeSelectorGroups(updated))
        }
        recordRecentServer(profileId, groupTag, outboundTag)
        when (val vpn = vpnController.state.value) {
            is VpnConnectionState.Connected ->
                if (vpn.profileId == profileId) {
                    vpnController.selectOutbound(profileId, groupTag, outboundTag)
                }
            else -> Unit
        }
        if (!previousTag.isNullOrBlank() && previousTag != outboundTag) {
            offerUndo("Сервер: $outboundTag") {
                val rollback = ConfigAnalyzer.selectServer(store.read(profileId).json, groupTag, previousTag)
                store.update(profileId, rollback)
                mutableState.update { it.copy(homeSelectorGroups = homeSelectorGroups(rollback)) }
                when (val live = vpnController.state.value) {
                    is VpnConnectionState.Connected ->
                        if (live.profileId == profileId) {
                            vpnController.selectOutbound(profileId, groupTag, previousTag)
                        }
                    else -> Unit
                }
            }
        }
    }

    fun recordRecentServer(profileId: String, groupTag: String, outboundTag: String) = operation(markBusy = false) {
        val location = ExitLocationResolver.fromServerLabel(outboundTag)
        recentServersStore.record(
            RecentServer(
                profileId = profileId,
                groupTag = groupTag,
                outboundTag = outboundTag,
                displayName = outboundTag,
                countryCode = location?.countryCode,
                flagEmoji = location?.flagEmoji,
                usedAtEpochMillis = System.currentTimeMillis(),
            ),
        )
        sessionSwitchHistory.record(profileId, outboundTag, location?.countryCode)
    }

    fun setReduceMotion(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setReduceMotion(enabled)
    }

    fun setAppLockEnabled(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setAppLockEnabled(enabled)
    }

    fun setNotifyExitIpChange(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setNotifyExitIpChange(enabled)
    }

    fun setCompactHome(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setCompactHome(enabled)
    }

    fun setBeginnerMode(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setBeginnerMode(enabled)
    }

    fun setOledBlack(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setOledBlack(enabled)
    }

    fun setUseDynamicColor(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setUseDynamicColor(enabled)
    }

    fun setHideExitIp(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setHideExitIp(enabled)
    }

    fun setFlagSecure(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setFlagSecure(enabled)
    }

    fun setHapticsEnabled(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setHapticsEnabled(enabled)
    }

    fun setShowSessionTimer(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setShowSessionTimer(enabled)
    }

    fun setAutoFailoverEnabled(enabled: Boolean) = operation(markBusy = false) {
        if (!ClientFeatureGate.features().autoFailover) {
            showMessage("Автосмена сервера отключена оператором.")
            return@operation
        }
        settingsStore.setAutoFailoverEnabled(enabled)
    }

    fun setIdleRemindEnabled(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setIdleRemindEnabled(enabled)
    }

    fun setClearClipboardAfterImport(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setClearClipboardAfterImport(enabled)
    }

    fun setMuteNotificationTrafficDetail(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setMuteNotificationTrafficDetail(enabled)
    }

    fun setConnectSoundEnabled(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setConnectSoundEnabled(enabled)
    }

    fun setAccentColor(color: AccentColor) = operation(markBusy = false) {
        settingsStore.setAccentColor(color)
    }

    fun setLargeText(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setLargeText(enabled)
    }

    fun setKeepScreenOnWhileConnecting(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setKeepScreenOnWhileConnecting(enabled)
    }

    fun setConfirmDisconnect(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setConfirmDisconnect(enabled)
    }

    fun setHideDeadServersDefault(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setHideDeadServersDefault(enabled)
    }

    fun setAutoPingOnServersOpen(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setAutoPingOnServersOpen(enabled)
        settingsAuditStore.append("autoPingOnServersOpen", enabled.toString())
    }

    fun setHideMap(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setHideMap(enabled)
    }

    fun setHideQuota(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setHideQuota(enabled)
    }

    fun setQuietMode(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setQuietMode(enabled)
        settingsAuditStore.append("quietMode", enabled.toString())
    }

    fun setHomeLayoutMode(mode: HomeLayoutMode) = operation(markBusy = false) {
        settingsStore.setHomeLayoutMode(mode)
    }

    fun setConfettiOnFirstConnect(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setConfettiOnFirstConnect(enabled)
    }

    fun setScheduleNightAutoConnect(enabled: Boolean) = operation(markBusy = false) {
        if (!ClientFeatureGate.features().vpnSchedule) {
            showMessage("Расписание VPN отключено оператором.")
            return@operation
        }
        settingsStore.setScheduleNightAutoConnect(enabled)
    }

    fun setScheduleMorningDisconnect(enabled: Boolean) = operation(markBusy = false) {
        if (!ClientFeatureGate.features().vpnSchedule) {
            showMessage("Расписание VPN отключено оператором.")
            return@operation
        }
        settingsStore.setScheduleMorningDisconnect(enabled)
    }

    fun setScheduleWorkConnect(enabled: Boolean) = operation(markBusy = false) {
        if (!ClientFeatureGate.features().vpnSchedule) {
            showMessage("Расписание VPN отключено оператором.")
            return@operation
        }
        settingsStore.setScheduleWorkConnect(enabled)
    }

    fun setAutoLockOnDisconnect(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setAutoLockOnDisconnect(enabled)
    }

    fun snoozeReconnectFifteenMinutes() = operation(markBusy = false) {
        val until = System.currentTimeMillis() + 15 * 60_000L
        settingsStore.setSnoozeReconnectUntil(until)
        settingsAuditStore.append("snoozeReconnect", until.toString())
        eventJournal.append("reconnect", "Snooze reconnect 15m")
    }

    fun clearSettingsAudit() = operation(markBusy = false) {
        settingsAuditStore.clear()
    }

    fun setServerNote(profileId: String, groupTag: String, outboundTag: String, note: String) =
        operation(markBusy = false) {
            serverNotesStore.set(ServerNotesStore.key(profileId, groupTag, outboundTag), note)
        }

    fun exportUiSettingsJson(): String {
        val s = state.value.settings
        return buildString {
            appendLine("{")
            appendLine("""  "themeMode": "${s.themeMode}",""")
            appendLine("""  "dnsMode": "${s.dnsMode}",""")
            appendLine("""  "accentColor": "${s.accentColor}",""")
            appendLine("""  "blockNonVpnTraffic": ${s.blockNonVpnTraffic},""")
            appendLine("""  "autoFailoverEnabled": ${s.autoFailoverEnabled},""")
            appendLine("""  "compactHome": ${s.compactHome},""")
            appendLine("""  "beginnerMode": ${s.beginnerMode},""")
            appendLine("""  "oledBlack": ${s.oledBlack},""")
            appendLine("""  "hideExitIp": ${s.hideExitIp},""")
            appendLine("""  "flagSecure": ${s.flagSecure},""")
            appendLine("""  "hapticsEnabled": ${s.hapticsEnabled},""")
            appendLine("""  "showSessionTimer": ${s.showSessionTimer},""")
            appendLine("""  "connectSoundEnabled": ${s.connectSoundEnabled},""")
            appendLine("""  "largeText": ${s.largeText},""")
            appendLine("""  "muteNotificationTrafficDetail": ${s.muteNotificationTrafficDetail},""")
            appendLine("""  "autoConnectTrustedWifi": ${s.autoConnectTrustedWifi},""")
            appendLine("""  "reduceMotion": ${s.reduceMotion}""")
            appendLine("}")
        }
    }

    fun completeOnboarding() = operation(markBusy = false) {
        settingsStore.setOnboardingCompleted(true)
    }

    fun setBlockNonVpnTraffic(enabled: Boolean) = operation(markBusy = false) {
        if (!ClientFeatureGate.features().killSwitch) {
            showMessage("Kill switch отключён оператором.")
            return@operation
        }
        settingsStore.setBlockNonVpnTraffic(enabled)
        settingsAuditStore.append("blockNonVpnTraffic", enabled.toString())
        vpnController.restartIfConnected("Смена блокировки трафика вне VPN")
    }

    fun setSortServersByPing(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setSortServersByPing(enabled)
    }

    fun setPowerMode(mode: PowerMode) = operation(markBusy = false) {
        settingsStore.setPowerMode(mode)
        settingsAuditStore.append("powerMode", mode.name)
    }

    fun setServerMode(mode: ServerMode) = operation(markBusy = false) {
        settingsStore.setServerMode(mode)
        settingsAuditStore.append("serverMode", mode.name)
    }

    /** Games / Video / Balance: persist preset and nudge DNS without MTU hacks. */
    fun applyExperiencePreset(mode: PowerMode) = operation(markBusy = false) {
        settingsStore.setPowerMode(mode)
        val dns = when (mode) {
            PowerMode.Speed -> DnsMode.Secure
            PowerMode.Battery -> DnsMode.Automatic
            PowerMode.Balanced -> DnsMode.Automatic
        }
        settingsStore.setDnsMode(dns)
        settingsAuditStore.append("experiencePreset", "${mode.name}/$dns")
        val label = when (mode) {
            PowerMode.Speed -> "Скорость: DoH через VPN"
            PowerMode.Battery -> "Стабильность: авто DNS"
            PowerMode.Balanced -> "Баланс: авто DNS"
        }
        showTip(label)
        if (vpnController.state.value is VpnConnectionState.Connected) {
            vpnController.restartIfConnected("Смена пресета $label")
        }
    }

    fun toggleFavoriteServer(profileId: String, groupTag: String, outboundTag: String) =
        operation(markBusy = false) {
            val now = favoriteServersStore.toggle(profileId, groupTag, outboundTag)
            showMessage(if (now) "В избранном." else "Убрано из избранного.")
        }

    fun restoreEncryptedBackup(uri: Uri) = operation {
        val result = profileBackupImporter.restore(uri)
        eventJournal.append("backup", "Восстановлено: ${result.importedProfiles}")
        showMessage(
            "Восстановлено профилей: ${result.importedProfiles}" +
                if (result.skipped > 0) ", пропущено: ${result.skipped}" else "",
        )
    }

    fun refreshAllSubscriptions() = operation {
        val ids = subscriptionSourceStore.ids().toList()
        if (ids.isEmpty()) {
            showMessage("Нет сохранённых URL подписок.")
            return@operation
        }
        var updated = 0
        var failed = 0
        var lastDiff: SubscriptionDiffResult? = null
        for (profileId in ids) {
            try {
                applySubscriptionRefresh(profileId)?.let { lastDiff = it }
                updated++
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                failed++
            }
        }
        if (updated > 0) {
            ruleSetAssets.ensureInstalled()
            vpnController.restartIfConnected("Подписки обновлены")
        }
        eventJournal.append("subscription", "Обновлено $updated, ошибок $failed")
        if (lastDiff != null) {
            pendingUndoAction = {
                store.update(lastDiff.profileId, lastDiff.backupJson)
                if (mutableState.value.settings.activeProfileId == lastDiff.profileId) {
                    mutableState.update {
                        it.copy(homeSelectorGroups = homeSelectorGroups(lastDiff.backupJson))
                    }
                }
                vpnController.restartIfConnected("Откат подписки")
            }
            mutableState.update {
                it.copy(
                    subscriptionDiff = lastDiff,
                    undoMessage = lastDiff.summaryRu,
                )
            }
        }
        showMessage(
            if (failed == 0) "Подписки обновлены: $updated."
            else "Подписки обновлены: $updated, ошибок: $failed.",
        )
    }

    fun setAutoConnectTrustedWifi(enabled: Boolean) = operation(markBusy = false) {
        if (!ClientFeatureGate.features().autoConnect) {
            showMessage("Автоподключение отключено оператором.")
            return@operation
        }
        settingsStore.setAutoConnectTrustedWifi(enabled)
        eventJournal.append("wifi", if (enabled) "Автоподключение Wi‑Fi вкл" else "Автоподключение Wi‑Fi выкл")
    }

    fun setTrustedWifiSsids(raw: String) = operation(markBusy = false) {
        settingsStore.setTrustedWifiSsids(raw)
    }

    fun runSpeedTest() = operation {
        val vpnOn = vpnController.state.value is com.quantumvpn.vpn.VpnConnectionState.Connected
        val result = SpeedTestProbe.run(vpnActive = vpnOn)
        speedTestHistoryStore.add(result.detail, result.ok)
        settingsStore.setLastSpeedTestDetail(result.detail)
        if (!mutableState.value.settings.incognitoSession) {
            eventJournal.append("speed", result.detail)
        }
        showMessage(if (result.ok) result.detail else "Спидтест: ${result.detail}")
    }

    fun runJammerTest() = operation {
        val result = com.quantumvpn.diagnostics.JammerProbe.run(isCellular = true)
        if (!mutableState.value.settings.incognitoSession) {
            eventJournal.append("jammer", result.summary)
        }
        showMessage(result.summary + "\n• " + result.points.joinToString("\n• "))
    }

    fun applyJammerRecommendation() = operation {
        val result = com.quantumvpn.diagnostics.JammerProbe.run(isCellular = true)
        settingsStore.setBypassPreset(result.recommendedPreset)
        settingsAuditStore.append("jammerApply", result.recommendedPreset.name)
        showMessage("${result.summary} — применено. Переподключите VPN.")
        vpnController.restartIfConnected("Тест глушилки")
    }

    fun setConnectionExperienceMode(mode: ConnectionExperienceMode) = operation(markBusy = false) {
        settingsStore.setConnectionExperienceMode(mode)
        settingsStore.setBypassPreset(mode.bypassPreset())
        mode.routingPresetOrNull()?.let { routingHint ->
            showTip("Режим «${mode.labelRu()}»: маршрутизация ${routingHint.title}, обход ${mode.bypassPreset().name}")
        } ?: showTip("Режим «${mode.labelRu()}»: обход ${mode.bypassPreset().name}")
        settingsAuditStore.append("connMode", mode.name)
    }

    fun setAdBlockLevel(level: com.quantumvpn.hardening.AdBlockLevel) = operation(markBusy = false) {
        settingsStore.setAdBlockLevel(level)
        vpnController.restartIfConnected("Смена уровня блокировки рекламы")
        showTip("Уровень блокировки рекламы: ${level.name}")
    }

    fun setAdBlockEnabled(enabled: Boolean) = operation(markBusy = false) {
        if (!ClientFeatureGate.features().adblock) {
            showMessage("Блокировка рекламы отключена оператором.")
            return@operation
        }
        settingsStore.setAdBlockEnabled(enabled)
        vpnController.restartIfConnected("Смена блокировки рекламы")
        showTip(if (enabled) "Блокировка рекламы включена" else "Блокировка рекламы выключена")
    }

    fun setAdBlockOnlineDns(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setAdBlockOnlineDns(enabled)
        vpnController.restartIfConnected("Смена онлайн DNS-фильтра")
        showTip(if (enabled) "Онлайн DNS-фильтр AdGuard включён" else "Только локальные списки")
    }

    fun setAdBlockTrackersOnly(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setAdBlockTrackersOnly(enabled)
        vpnController.restartIfConnected("Смена режима трекеров ad-block")
        showTip("Режим трекеров обновлён")
    }

    fun setAdBlockWhitelist(raw: String) = operation(markBusy = false) {
        settingsStore.setAdBlockWhitelist(raw)
        vpnController.restartIfConnected("Смена whitelist ad-block")
        showTip("Whitelist сохранён")
    }

    fun setAdBlockCategories(categories: Set<com.quantumvpn.hardening.AdBlockCategory>) =
        operation(markBusy = false) {
            settingsStore.setAdBlockCategories(categories)
            vpnController.restartIfConnected("Смена категорий блокировки контента")
            val labels = categories.joinToString { it.name }
            showTip(if (categories.isEmpty()) "Категории контента выключены" else "Блокировка категорий: $labels")
        }

    /**
     * Перед подключением: Maximum + AdGuard DoH, Safe mode off,
     * попытка смягчить Strict Private DNS / открыть системные настройки.
     */
    suspend fun prepareAdBlockBeforeConnect(
        context: android.content.Context,
        openPrivateDnsSettingsIfStrict: Boolean = true,
    ): com.quantumvpn.hardening.AdBlockConnectPreflight.Result {
        val result = com.quantumvpn.hardening.AdBlockConnectPreflight.prepare(
            context = context.applicationContext,
            settingsStore = settingsStore,
            openPrivateDnsSettingsIfStrict = openPrivateDnsSettingsIfStrict,
        )
        if (result.settingsApplied || result.openedPrivateDnsSettings || result.privateDnsFixed) {
            showTip(result.tip)
        }
        return result
    }

    fun setHomeVisualTheme(theme: HomeVisualTheme) = operation(markBusy = false) {
        settingsStore.setHomeVisualTheme(theme)
        showTip(
            when (theme) {
                HomeVisualTheme.Globe3d -> "Home: 3D-глобус"
                HomeVisualTheme.Classic -> "Home: классическая карта"
            },
        )
    }

    fun setSofterBypassOnWifi(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setSofterBypassOnWifi(enabled)
    }

    fun setAdaptiveDpiEnabled(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setAdaptiveDpiEnabled(enabled)
    }

    fun setIncognitoSession(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setIncognitoSession(enabled)
        showTip(if (enabled) "Инкогнито: журнал сессии отключён" else "Инкогнито выкл")
    }

    fun setBlockWebRtcMdns(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setBlockWebRtcMdns(enabled)
        showTip(if (enabled) "WebRTC/mDNS блокируются в runtime" else "WebRTC/mDNS без блокировки")
    }

    fun setQuietNightReconnect(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setQuietNightReconnect(enabled)
    }

    fun setQoeMonitorEnabled(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setQoeMonitorEnabled(enabled)
        showTip(if (enabled) "QoE-монитор включён" else "QoE-монитор выкл")
    }

    fun setStealthUntil(epochMillis: Long) = operation(markBusy = false) {
        settingsStore.setStealthUntilEpochMillis(epochMillis)
    }

    fun setStealthMode(enabled: Boolean) = operation(markBusy = false) {
        if (!ClientFeatureGate.features().stealthMode) {
            showMessage("Stealth mode отключён оператором.")
            return@operation
        }
        settingsStore.setStealthMode(enabled)
        if (enabled) {
            showTip("Stealth: усиленная маскировка трафика (анти-DPI) включена")
        }
    }

    fun startStealthThirtyMinutes() = operation(markBusy = false) {
        val until = System.currentTimeMillis() + 30L * 60L * 1000L
        settingsStore.setStealthUntilEpochMillis(until)
        settingsStore.setIncognitoSession(true)
        showTip("Stealth 30 мин: без истории до окончания")
    }

    fun liveCheckActiveServer() = operation {
        val profileId = mutableState.value.settings.activeProfileId
            ?: throw IllegalStateException("Нет активного профиля.")
        val selected = mutableState.value.homeSelectorGroups.primaryGroup()?.selected
            ?: throw IllegalStateException("Нет выбранного сервера.")
        val json = store.read(profileId).json
        val desc = ConfigAnalyzer.outboundDescriptions(json)[selected]
            ?: throw IllegalStateException("Сервер не найден в профиле.")
        val host = desc.serverHost
        val port = desc.endpoint
            ?.substringAfterLast(':')
            ?.toIntOrNull()
        val type = desc.type.lowercase()
        if (com.quantumvpn.olcrtc.OlcrtcProtocol.isLoopbackSocks(desc)) {
            showTip("olcrtc: доступность проверяется движком при подключении.")
            return@operation
        }
        val useTls = type !in setOf("hysteria", "hysteria2", "tuic", "wireguard", "shadowsocks")
        val result = com.quantumvpn.vpn.LiveServerChecker.check(host, port, useTls = useTls)
        eventJournal.append("live_check", result.detail)
        showTip(result.detail)
        if (!result.ok) {
            showMessage("Сервер недоступен до connect: ${result.detail}")
        }
    }

    fun setSubscriptionRefreshHours(hours: Int) = operation(markBusy = false) {
        settingsStore.setSubscriptionRefreshHours(hours)
        showTip("Автообновление подписок каждые ${hours.coerceIn(1, 24)} ч (всегда включено)")
    }

    fun setSubscriptionPriorityIds(csv: String) = operation(markBusy = false) {
        settingsStore.setSubscriptionPriorityIds(csv)
    }

    fun setHomeBlocksOrder(order: String) = operation(markBusy = false) {
        settingsStore.setHomeBlocksOrder(order)
    }

    fun recordConnectFailureForAdaptiveDpi() = operation(markBusy = false) {
        if (!mutableState.value.settings.adaptiveDpiEnabled) return@operation
        val next = mutableState.value.settings.connectFailStreak + 1
        settingsStore.setConnectFailStreak(next)
        val upgrade = when {
            next >= 4 -> com.quantumvpn.hardening.BypassPreset.Aggressive
            next >= 2 -> com.quantumvpn.hardening.BypassPreset.Tele2
            else -> null
        }
        if (upgrade != null && mutableState.value.settings.bypassPreset.ordinal < upgrade.ordinal) {
            settingsStore.setBypassPreset(upgrade)
            showTip("Adaptive DPI: усилили обход → ${upgrade.name}")
        }
    }

    fun recordConnectSuccessForAdaptiveDpi() = operation(markBusy = false) {
        settingsStore.setConnectFailStreak(0)
    }

    fun raceDnsLatency() = operation {
        val samples = DnsLatencyProbe.race()
        val summary = DnsLatencyProbe.format(samples)
        eventJournal.append("dns_latency", summary)
        val best = samples.firstOrNull { it.millis != null }
        if (best != null) {
            val preset = com.quantumvpn.config.DnsPresetCatalog.presets
                .firstOrNull { it.title == best.title }
            if (preset != null) {
                settingsStore.setDnsOverride(preset.hostname, preset.ipv4)
                settingsStore.setDnsOverrideEnabled(true)
            }
        }
        showMessage(summary)
    }

    fun clearSpeedTestHistory() = operation(markBusy = false) {
        speedTestHistoryStore.clear()
        showMessage("История спидтеста очищена.")
    }

    fun logEvent(kind: String, message: String) = operation(markBusy = false) {
        eventJournal.append(kind, message)
    }

    fun showTip(message: String) = operation(markBusy = false) {
        if (mutableState.value.settings.quietMode) return@operation
        showMessage(message.take(480))
    }

    fun clearEventJournal() = operation(markBusy = false) {
        eventJournal.clear()
        showMessage("Журнал очищен.")
    }

    fun renameProfile(id: String, name: String) = operation {
        store.rename(id, name)
        mutableState.update { state ->
            state.copy(
                editor = state.editor?.takeIf { it.profileId == id }?.copy(profileName = name.trim())
                    ?: state.editor,
            )
        }
        showMessage("Профиль переименован.")
    }

    fun deleteProfile(id: String) = operation {
        val stored = runCatching { store.read(id) }.getOrNull()
        val wasActive = mutableState.value.settings.activeProfileId == id
        val name = stored?.metadata?.name ?: id
        val engines = olcrtcEngineStore.read(id)
        store.delete(id)
        olcrtcEngineStore.remove(id)
        subscriptionSourceStore.remove(id)
        happRoutingStore.remove(id)
        bootstrapCache.removeProfile(id)
        mutableState.update { it.copy(refreshableProfileIds = it.refreshableProfileIds - id) }
        if (wasActive) settingsStore.setActiveProfile(store.profiles.value.firstOrNull()?.id)
        if (mutableState.value.editor?.profileId == id) closeEditor(force = true)
        if (stored != null) {
            offerUndo("Профиль «$name» удалён") {
                val meta = store.create(name, stored.json, stored.metadata.source)
                olcrtcEngineStore.write(meta.id, engines)
                if (wasActive) settingsStore.setActiveProfile(meta.id)
            }
        } else {
            showMessage("Профиль удалён.")
        }
    }

    fun openEditor(id: String) = operation(markBusy = false) {
        showMessage("Редактирование JSON отключено.")
    }

    fun closeEditor(force: Boolean = false): Boolean {
        val editor = mutableState.value.editor ?: return true
        if (editor.hasUnsavedChanges && !force) return false
        mutableState.update { it.copy(editor = null) }
        return true
    }

    fun updateEditorText(text: String) {
        mutableState.update { state ->
            val editor = state.editor ?: return@update state
            state.copy(editor = editor.withText(text))
        }
    }

    fun updateSearch(search: String) {
        mutableState.update { state ->
            state.copy(editor = state.editor?.copy(search = search))
        }
    }

    fun formatEditor() {
        val editor = mutableState.value.editor ?: return
        try {
            updateEditorText(JsonConfig.format(editor.text))
            setEditorValidation("JSON отформатирован.", true)
        } catch (_: Exception) {
            setEditorValidation("Сначала исправьте синтаксис JSON.", false)
        }
    }

    fun validateEditor() = operation(markBusy = false) {
        val editor = mutableState.value.editor ?: return@operation
        when (val result = withContext(Dispatchers.IO) { validator.validate(editor.text) }) {
            ConfigValidationResult.Valid -> setEditorValidation("Конфигурация корректна.", true)
            is ConfigValidationResult.Invalid -> setEditorValidation(result.message, false)
        }
    }

    fun saveEditor() = operation {
        val editor = mutableState.value.editor ?: return@operation
        store.update(editor.profileId, editor.text)
        val stored = store.read(editor.profileId)
        mutableState.update { it.copy(editor = editorState(stored)) }
        showMessage("Профиль сохранён.")
    }

    fun restoreBackup() = operation {
        val editor = mutableState.value.editor ?: return@operation
        store.restoreBackup(editor.profileId)
        val stored = store.read(editor.profileId)
        mutableState.update { it.copy(editor = editorState(stored)) }
        showMessage("Backup восстановлен; прежняя текущая версия стала backup.")
    }

    fun selectServer(selectorTag: String, serverTag: String) {
        val editor = mutableState.value.editor ?: return
        try {
            updateEditorText(ConfigAnalyzer.selectServer(editor.text, selectorTag, serverTag))
            setEditorValidation("Выбор записан в selector.default. Нажмите «Сохранить».", true)
        } catch (error: Exception) {
            setEditorValidation(error.userMessage("Не удалось выбрать сервер."), false)
        }
    }

    fun createManagedSelector() {
        val editor = mutableState.value.editor ?: return
        try {
            updateEditorText(ConfigAnalyzer.addManagedSelector(editor.text, editor.serverTags))
            setEditorValidation("zapret-proxy добавлен явно. Нажмите «Сохранить».", true)
        } catch (error: Exception) {
            setEditorValidation(error.userMessage("Не удалось создать selector."), false)
        }
    }

    fun setTheme(mode: ThemeMode) = operation(markBusy = false) {
        settingsStore.setThemeMode(mode)
    }

    fun setRawEditorLineWrap(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setRawEditorLineWrap(enabled)
    }

    fun setDnsMode(mode: DnsMode) = operation(markBusy = false) {
        settingsStore.setDnsMode(mode)
        settingsAuditStore.append("dnsMode", mode.name)
        vpnController.restartIfConnected("Смена режима DNS")
    }

    fun panicWipeProfiles() = operation {
        vpnController.stop()
        val ids = store.profiles.value.map { it.id }
        for (id in ids) {
            store.delete(id)
            olcrtcEngineStore.remove(id)
            subscriptionSourceStore.remove(id)
            happRoutingStore.remove(id)
            bootstrapCache.removeProfile(id)
        }
        olcrtcEngineStore.wipe()
        settingsStore.setActiveProfile(null)
        settingsAuditStore.append("panicWipe", ids.size.toString())
        eventJournal.append("security", "Panic wipe: ${ids.size} profiles")
        mutableState.update {
            it.copy(
                profiles = emptyList(),
                editor = null,
                refreshableProfileIds = emptySet(),
                subscriptionQuota = null,
            )
        }
        showMessage("Panic wipe: профили удалены.")
    }

    /** Reset network overlays without deleting profiles (fixes "no traffic" after bad DPI mode). */
    fun panicResetNetworkOverlays() = operation(markBusy = false) {
        settingsStore.setSafeModeConnect(false)
        settingsStore.setCarrierBypassEnabled(true)
        settingsStore.setBypassPreset(com.quantumvpn.hardening.BypassPreset.Tele2)
        settingsStore.setCarrierBypassAlwaysAggressive(true)
        settingsStore.setDnsMode(DnsMode.Secure)
        settingsStore.setProxyIpv4Only(true)
        settingsAuditStore.append("panicResetOverlays", "tele2")
        eventJournal.append("network", "Panic reset: DPI Оператор+усиленный, DNS Secure, safe mode off")
        showTip("Сброс сети: обход Оператор (усиленный), DNS Secure. Переподключаем…")
        vpnController.restartIfConnected("Сброс сетевых оверлеев")
    }

    fun setProxyIpv4Only(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setProxyIpv4Only(enabled)
        vpnController.restartIfConnected("Смена IP-стратегии DNS")
    }

    fun setDnsOverrideEnabled(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setDnsOverrideEnabled(enabled)
        vpnController.restartIfConnected("Смена DNS-переопределения")
    }

    fun setDnsOverride(hostname: String, ipv4Address: String) = operation(markBusy = false) {
        settingsStore.setDnsOverride(hostname, ipv4Address)
        vpnController.restartIfConnected("Смена DNS-переопределения")
    }

    fun setUpdateChannel(channel: UpdateChannel) = operation(markBusy = false) {
        settingsStore.setUpdateChannel(channel)
    }

    fun setVpnHidingBlockLocalEndpoints(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setVpnHidingBlockLocalEndpoints(enabled)
        vpnController.restartIfConnected("Смена защиты от localhost-чекеров")
    }

    fun setVpnHidingNeutralSessionName(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setVpnHidingNeutralSessionName(enabled)
        vpnController.restartIfConnected("Смена имени VPN-сессии")
    }

    fun setCarrierBypassEnabled(enabled: Boolean) = operation(markBusy = false) {
        if (!ClientFeatureGate.features().carrierBypass) {
            showMessage("Обход оператора отключён в панели.")
            return@operation
        }
        settingsStore.setCarrierBypassEnabled(enabled)
        settingsAuditStore.append("carrierBypass", enabled.toString())
        vpnController.restartIfConnected("Смена обхода DPI/лимитов")
    }

    fun setCarrierBypassAlwaysAggressive(enabled: Boolean) = operation(markBusy = false) {
        settingsStore.setCarrierBypassAlwaysAggressive(enabled)
        settingsAuditStore.append("carrierBypassAggressive", enabled.toString())
        vpnController.restartIfConnected("Смена агрессивного обхода DPI")
    }

    fun setBypassPreset(preset: com.quantumvpn.hardening.BypassPreset) = operation(markBusy = false) {
        settingsStore.setBypassPreset(preset)
        settingsAuditStore.append("bypassPreset", preset.name)
        vpnController.restartIfConnected("Смена пресета обхода DPI")
    }

    fun setVpnHidingTunMtuMode(mode: TunMtuMode) = operation(markBusy = false) {
        settingsStore.setVpnHidingTunMtuMode(mode)
        vpnController.restartIfConnected("Смена MTU для скрытия VPN")
    }

    fun consumeMessage() {
        mutableState.update { it.copy(message = null) }
    }

    private suspend fun preview(
        raw: String,
        source: ProfileSource,
        suggestedName: String,
        sourceDescription: String,
        sourceUrl: String? = null,
        routingHeader: String? = null,
    ) {
        val parsed = withContext(Dispatchers.Default) {
            ImportParser.parse(raw, source, suggestedName, routingHeader = routingHeader)
        }
        val candidate = parsed.candidate
        val baseJson = candidate.toJson()
        val json = if (candidate is ImportCandidate.Managed) {
            val installed = withContext(Dispatchers.IO) { ruleSetAssets.ensureInstalled() }
            withContext(Dispatchers.Default) {
                RoutingConfigEditor.apply(
                    baseJson,
                    RoutingPreset.AllThroughVpn,
                    emptyList(),
                    installed,
                ).json
            }
        } else {
            baseJson
        }
        // Preview compile without binding to a profile id yet (confirmImport persists).
        val previewJson = if (parsed.routing is HappRoutingImport.None) {
            json
        } else {
            val installed = withContext(Dispatchers.IO) { ruleSetAssets.ensureInstalled() }
            val ephemeral = when (val routing = parsed.routing) {
                HappRoutingImport.Disable -> com.quantumvpn.routing.HappRoutingCatalog(enabled = false)
                is HappRoutingImport.Profiles -> com.quantumvpn.routing.HappRoutingCatalog(
                    enabled = true,
                    activeName = routing.updates.lastOrNull { it.activate }?.profile?.name
                        ?: routing.updates.first().profile.name,
                    profiles = routing.updates.map { it.profile }.distinctBy { it.name },
                )
                HappRoutingImport.None -> com.quantumvpn.routing.HappRoutingCatalog()
            }
            withContext(Dispatchers.Default) {
                HappRoutingCompiler.applyToProfileJson(json, ephemeral, installed)
            }
        }
        requireValid(previewJson)
        val appendTargets = if (candidate is ImportCandidate.Managed && candidate.servers.size == 1) {
            buildList {
                for (profile in mutableState.value.profiles) {
                    if (runCatching { ManagedProfileEditor.isManaged(store.read(profile.id).json) }
                            .getOrDefault(false)
                    ) {
                        add(profile)
                    }
                }
            }
        } else {
            emptyList()
        }
        mutableState.update {
            it.copy(
                importPreview = ImportPreviewState(
                    suggestedName = SecretRedactor.redactInline(candidate.suggestedName),
                    sourceDescription = sourceDescription,
                    serverCount = candidate.serverCount(),
                    serverLabels = candidate.serverLabels(),
                    activityWarning = importWarnings(previewJson),
                    appendTargets = appendTargets,
                    candidate = candidate,
                    preparedJson = previewJson,
                    sourceUrl = sourceUrl,
                    routing = parsed.routing,
                ),
                message = null,
            )
        }
    }

    private suspend fun applyRoutingOverlay(
        profileId: String,
        routing: HappRoutingImport,
        baseJson: String,
    ): String {
        val catalog = when (routing) {
            HappRoutingImport.None -> happRoutingStore.get(profileId)
            else -> happRoutingStore.applyImport(profileId, routing)
        }
        if (catalog.profiles.isEmpty()) return baseJson
        val installed = withContext(Dispatchers.IO) { ruleSetAssets.ensureInstalled() }
        return withContext(Dispatchers.Default) {
            HappRoutingCompiler.applyToProfileJson(baseJson, catalog, installed)
        }
    }

    private fun importWarnings(json: String): String? = buildList {
        ImportedConfigActivityScanner.warning(ImportedConfigActivityScanner.scan(json))
            ?.let(::add)
        addAll(ConfigAnalyzer.dnsWarnings(json))
    }.takeIf(List<String>::isNotEmpty)?.joinToString("\n")

    private fun ImportCandidate.toJson(): String = when (this) {
        is ImportCandidate.RawJson -> json
        is ImportCandidate.Managed -> buildJson()
        is ImportCandidate.WireGuard -> json
    }

    private fun ImportCandidate.serverCount(): Int = when (this) {
        is ImportCandidate.RawJson -> runCatching {
            ConfigAnalyzer.serverOutboundTags(json).size
        }.getOrDefault(0)
        is ImportCandidate.Managed -> servers.size
        is ImportCandidate.WireGuard -> 1
    }

    private fun ImportCandidate.serverLabels(): List<String> = when (this) {
        is ImportCandidate.RawJson -> runCatching {
            ConfigAnalyzer.serverOutboundTags(json)
        }.getOrDefault(emptyList())
        is ImportCandidate.Managed -> servers.map(ManagedServer::displayName)
        is ImportCandidate.WireGuard -> listOfNotNull(
            endpointLabel?.let { "$protocolName · $it" } ?: protocolName,
        )
    }.take(8).map(SecretRedactor::redactInline)

    private suspend fun requireValid(rawJson: String) {
        when (val result = withContext(Dispatchers.IO) { validator.validate(rawJson) }) {
            ConfigValidationResult.Valid -> Unit
            is ConfigValidationResult.Invalid -> throw ImportException(result.message)
        }
    }

    private fun editorState(profile: StoredProfile): ProfileEditorState = ProfileEditorState(
        profileId = profile.metadata.id,
        profileName = profile.metadata.name,
        originalText = profile.json,
        text = profile.json,
        selectors = runCatching { ConfigAnalyzer.selectorGroups(profile.json) }.getOrDefault(emptyList()),
        serverTags = runCatching { ConfigAnalyzer.serverOutboundTags(profile.json) }.getOrDefault(emptyList()),
        hasBackup = profile.hasBackup,
    )

    private fun homeSelectorGroups(json: String): List<RuntimeSelectorGroup> {
        val selectors = ConfigAnalyzer.selectorGroups(json)
        if (selectors.isEmpty()) return emptyList()
        val descriptions = ConfigAnalyzer.outboundDescriptions(json)
        val groups = selectors.map { group ->
            RuntimeSelectorGroup(
                tag = group.tag,
                type = "selector",
                selected = group.default
                    ?.takeIf { it in group.outbounds }
                    ?: group.outbounds.firstOrNull().orEmpty(),
                selectable = true,
                items = group.outbounds.map { tag ->
                    val description = descriptions[tag]
                    RuntimeOutboundItem(
                        tag = tag,
                        type = com.quantumvpn.olcrtc.OlcrtcProtocol.displayType(description) ?: "proxy",
                        endpoint = description?.endpoint,
                        pingMillis = null,
                        pingMeasuredAtEpochSeconds = null,
                    )
                },
            )
        }
        return groups.forServerUi()
    }

    private suspend fun writeOlcrtcEngines(profileId: String, servers: List<com.quantumvpn.profiles.ManagedServer>) {
        val engines = buildMap<String, com.quantumvpn.olcrtc.OlcrtcSettings> {
            ManagedProfileFactory.taggedServers(servers).forEachIndexed { index, tagged ->
                servers[index].olcrtc?.let { put(tagged.tag, it) }
            }
        }
        olcrtcEngineStore.write(profileId, engines)
    }

    private suspend fun appendOlcrtcEngine(profileId: String, oldJson: String, server: com.quantumvpn.profiles.ManagedServer) {
        val settings = server.olcrtc ?: return
        val baseTag = ManagedProfileFactory.taggedServers(listOf(server)).single().tag
        val usedTags = ConfigAnalyzer.outboundDescriptions(oldJson).keys.toSet()
        var tag = baseTag
        var suffix = 2
        while (tag in usedTags) tag = "$baseTag-${suffix++}"
        olcrtcEngineStore.write(profileId, olcrtcEngineStore.read(profileId) + (tag to settings))
    }

    private fun ProfileEditorState.withText(value: String): ProfileEditorState = copy(
        text = value,
        validationMessage = null,
        validationSuccessful = false,
        selectors = runCatching { ConfigAnalyzer.selectorGroups(value) }.getOrDefault(emptyList()),
        serverTags = runCatching { ConfigAnalyzer.serverOutboundTags(value) }.getOrDefault(emptyList()),
    )

    private fun setEditorValidation(message: String, successful: Boolean) {
        mutableState.update { state ->
            state.copy(
                editor = state.editor?.copy(
                    validationMessage = message,
                    validationSuccessful = successful,
                ),
            )
        }
    }

    private fun operation(markBusy: Boolean = true, block: suspend () -> Unit) {
        viewModelScope.launch {
            if (markBusy) mutableState.update { it.copy(busy = true) }
            try {
                block()
            } catch (error: Exception) {
                showMessage(error.userMessage("Операция не выполнена."))
            } finally {
                if (markBusy) mutableState.update { it.copy(busy = false) }
            }
        }
    }

    private fun showMessage(message: String) {
        mutableState.update { it.copy(message = message) }
    }

    private fun Throwable.userMessage(fallback: String): String =
        SecretRedactor.redactInline(message?.takeIf(String::isNotBlank)?.take(320) ?: fallback)

    private suspend fun fetchSubscriptionPayload(url: String): com.quantumvpn.importer.SubscriptionPayload {
        subscriptionSourceHealthStore.backoffMessage(url)?.let { throw ImportException(it) }
        if (!subscriptionSourceHealthStore.canFetch(url)) {
            throw ImportException("Источник подписки временно в карантине.")
        }
        return try {
            val payload = withContext(Dispatchers.IO) { subscriptionFetcher.fetch(url) }
            subscriptionSourceHealthStore.recordSuccess(url)
            payload
        } catch (error: ImportException) {
            if (error.httpStatus == 429) {
                subscriptionSourceHealthStore.record429(url)
            } else {
                subscriptionSourceHealthStore.recordHardFailure(url)
            }
            throw error
        }
    }

    class Factory(
        private val store: ProfileStore,
        private val settingsStore: UiSettingsStore,
        private val validator: ConfigValidator,
        private val importReader: AndroidImportReader,
        private val subscriptionFetcher: SubscriptionFetcher,
        private val subscriptionSourceStore: SubscriptionSourceStore,
        private val vpnController: VpnController,
        private val bootstrapCache: BootstrapCache,
        private val ruleSetAssets: RuleSetAssetManager,
        private val happRoutingStore: HappRoutingProfileStore,
        private val olcrtcEngineStore: com.quantumvpn.olcrtc.OlcrtcEngineStore,
        private val recentServersStore: RecentServersStore,
        private val favoriteServersStore: FavoriteServersStore,
        private val pinnedServersStore: PinnedServersStore,
        private val profileBackupImporter: ProfileBackupImporter,
        private val eventJournal: EventJournalStore,
        private val sessionSwitchHistory: SessionSwitchHistoryStore,
        private val subscriptionQuotaStore: SubscriptionQuotaStore,
        private val disconnectReasonStore: DisconnectReasonStore,
        private val speedTestHistoryStore: SpeedTestHistoryStore,
        private val connectDurationStore: ConnectDurationStore,
        private val serverNotesStore: ServerNotesStore,
        private val sessionTrafficHistoryStore: SessionTrafficHistoryStore,
        private val settingsAuditStore: SettingsAuditStore,
        private val reliabilityReportStore: ReliabilityReportStore,
        private val deadServerQuarantineStore: DeadServerQuarantineStore,
        private val serverReliabilityStore: ServerReliabilityStore,
        private val lastKnownGoodStore: LastKnownGoodStore,
        private val subscriptionSourceHealthStore: SubscriptionSourceHealthStore,
        private val importClipboardClear: () -> Unit,
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            require(modelClass.isAssignableFrom(ProfilesViewModel::class.java))
            return ProfilesViewModel(
                store,
                settingsStore,
                validator,
                importReader,
                subscriptionFetcher,
                subscriptionSourceStore,
                vpnController,
                bootstrapCache,
                ruleSetAssets,
                happRoutingStore,
                olcrtcEngineStore,
                recentServersStore,
                favoriteServersStore,
                pinnedServersStore,
                profileBackupImporter,
                eventJournal,
                sessionSwitchHistory,
                subscriptionQuotaStore,
                disconnectReasonStore,
                speedTestHistoryStore,
                connectDurationStore,
                serverNotesStore,
                sessionTrafficHistoryStore,
                settingsAuditStore,
                reliabilityReportStore,
                deadServerQuarantineStore,
                serverReliabilityStore,
                lastKnownGoodStore,
                subscriptionSourceHealthStore,
                importClipboardClear,
            ) as T
        }
    }
}
