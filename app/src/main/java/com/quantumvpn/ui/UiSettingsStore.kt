package com.quantumvpn.ui

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.quantumvpn.BuildConfig
import com.quantumvpn.config.DnsMode
import com.quantumvpn.config.DnsOverride
import com.quantumvpn.hardening.TunMtuMode
import com.quantumvpn.hardening.VpnHidingOptions
import com.quantumvpn.hardening.AdBlockCategory
import com.quantumvpn.updates.UpdateChannel
import java.io.IOException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map

enum class ThemeMode {
    System,
    Light,
    Dark,
}

enum class PowerMode {
    Battery,
    Balanced,
    Speed,
}

enum class AccentColor {
    Green,
    Blue,
    Teal,
    Amber,
    Purple,
    Rose,
    Orange,
    Mint,
}

enum class HomeVisualTheme {
    Classic,
    Globe3d,
}

enum class HomeLayoutMode {
    Standard,
    MapOnly,
    MetricsOnly,
    Expert,
}

/** Server selection bias: Standard (balanced), Gaming (low latency), Movie (throughput). */
enum class ServerMode {
    Standard,
    Gaming,
    Movie,
}

data class UiSettings(
    val themeMode: ThemeMode = ThemeMode.System,
    val activeProfileId: String? = null,
    val rawEditorLineWrap: Boolean = false,
    val dnsMode: DnsMode = DnsMode.FromJson,
    val proxyIpv4Only: Boolean = true,
    val dnsOverride: DnsOverride = DnsOverride(),
    val updateChannel: UpdateChannel = UpdateChannel.Stable,
    val vpnHiding: VpnHidingOptions = VpnHidingOptions(
        tunMtuMode = TunMtuMode.CoreDefault,
    ),
    val onboardingCompleted: Boolean = false,
    val blockNonVpnTraffic: Boolean = false,
    val sortServersByPing: Boolean = true,
    val powerMode: PowerMode = PowerMode.Balanced,
    val serverMode: ServerMode = ServerMode.Standard,
    val autoConnectTrustedWifi: Boolean = false,
    val trustedWifiSsids: String = "",
    val reduceMotion: Boolean = false,
    val appLockEnabled: Boolean = true,
    val notifyExitIpChange: Boolean = true,
    val compactHome: Boolean = false,
    val beginnerMode: Boolean = false,
    val oledBlack: Boolean = false,
    val hideExitIp: Boolean = false,
    val flagSecure: Boolean = true,
    val hapticsEnabled: Boolean = true,
    val showSessionTimer: Boolean = true,
    val autoFailoverEnabled: Boolean = true,
    val idleRemindEnabled: Boolean = true,
    val clearClipboardAfterImport: Boolean = true,
    val muteNotificationTrafficDetail: Boolean = false,
    val connectSoundEnabled: Boolean = false,
    val accentColor: AccentColor = AccentColor.Green,
    val largeText: Boolean = false,
    val keepScreenOnWhileConnecting: Boolean = false,
    val confirmDisconnect: Boolean = false,
    val hideDeadServersDefault: Boolean = false,
    val autoPingOnServersOpen: Boolean = true,
    val hideMap: Boolean = false,
    val homeVisualTheme: HomeVisualTheme = HomeVisualTheme.Globe3d,
    val hideQuota: Boolean = false,
    val quietMode: Boolean = false,
    val homeLayoutMode: HomeLayoutMode = HomeLayoutMode.Standard,
    val confettiOnFirstConnect: Boolean = false,
    val scheduleNightAutoConnect: Boolean = false,
    val scheduleMorningDisconnect: Boolean = false,
    val autoLockOnDisconnect: Boolean = false,
    val snoozeReconnectUntilEpochMillis: Long = 0L,
    val lastSeenChangelogVersion: String = "",
    val biometricLockEnabled: Boolean = true,
    val requireUnlockToDisconnect: Boolean = false,
    val requireUnlockToChangeServer: Boolean = false,
    val highContrast: Boolean = false,
    val useDynamicColor: Boolean = false,
    val coachMarksDismissed: Boolean = false,
    val safeModeConnect: Boolean = false,
    val failoverCooldownUntilEpochMillis: Long = 0L,
    val customDohUrl: String = "",
    val customDotUrl: String = "",
    val dismissedCoachMarkScreens: Set<String> = emptySet(),
    val scheduleWorkConnect: Boolean = false,
    val skipAutoConnectWhenRoaming: Boolean = true,
    val autoConnectOnCellular: Boolean = false,
    val timeRoutingEnabled: Boolean = false,
    val tipsCarouselDismissed: Boolean = false,
    /** Happ-like TLS fragment / record_fragment on proxy outbounds (all carriers). */
    val carrierBypassEnabled: Boolean = true,
    /** Kept for UI compatibility; mapped into [bypassPreset]. Default on → Агрессивный на блокировках. */
    val carrierBypassAlwaysAggressive: Boolean = true,
    val bypassPreset: com.quantumvpn.hardening.BypassPreset =
        com.quantumvpn.hardening.BypassPreset.Tele2,
    val connectionExperienceMode: ConnectionExperienceMode = ConnectionExperienceMode.Normal,
    val adBlockLevel: com.quantumvpn.hardening.AdBlockLevel =
        com.quantumvpn.hardening.AdBlockLevel.Maximum,
    val adBlockEnabled: Boolean = true,
    val adBlockOnlineDns: Boolean = true,
    val adBlockTrackersOnly: Boolean = false,
    val adBlockWhitelist: String = "",
    val adBlockCategories: Set<AdBlockCategory> = emptySet(),
    val cumulativeBlocked: Long = 0L,
    val softerBypassOnWifi: Boolean = true,
    val adaptiveDpiEnabled: Boolean = true,
    val connectFailStreak: Int = 0,
    val incognitoSession: Boolean = false,
    val homeBlocksOrder: String = "modes,tools,server,subscription,adblock",
    val subscriptionPriorityIds: String = "",
    val subscriptionRefreshHours: Int = 1,
    val lastSpeedTestDetail: String = "",
    val blockWebRtcMdns: Boolean = true,
    val quietNightReconnect: Boolean = true,
    val qoeMonitorEnabled: Boolean = true,
    val stealthUntilEpochMillis: Long = 0L,
    val stealthMode: Boolean = true,
)

private val Context.uiSettingsDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "ui_settings",
)

class UiSettingsStore(
    context: Context,
    private val buildDefaultUpdateChannel: UpdateChannel =
        UpdateChannel.valueOf(BuildConfig.DEFAULT_UPDATE_CHANNEL),
    private val updateChannelBuildId: String =
        "${BuildConfig.VERSION_CODE}:${BuildConfig.VERSION_NAME}",
) {
    private val dataStore = context.applicationContext.uiSettingsDataStore

    val settings: Flow<UiSettings> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { preferences ->
            UiSettings(
                themeMode = preferences[THEME_MODE]
                    ?.let { stored -> ThemeMode.entries.firstOrNull { it.name == stored } }
                    ?: ThemeMode.Dark,
                activeProfileId = preferences[ACTIVE_PROFILE_ID],
                rawEditorLineWrap = preferences[RAW_EDITOR_LINE_WRAP] ?: false,
                dnsMode = preferences[DNS_MODE]
                    ?.let { stored -> DnsMode.entries.firstOrNull { it.name == stored } }
                    ?: DnsMode.FromJson,
                proxyIpv4Only = preferences[PROXY_IPV4_ONLY] ?: true,
                dnsOverride = DnsOverride(
                    enabled = preferences[DNS_OVERRIDE_ENABLED] ?: true,
                    hostname = preferences[DNS_OVERRIDE_HOSTNAME] ?: DnsOverride.DEFAULT_HOSTNAME,
                    ipv4Address = preferences[DNS_OVERRIDE_IPV4] ?: DnsOverride.DEFAULT_IPV4_ADDRESS,
                ),
                updateChannel = resolveUpdateChannel(
                    storedChannel = preferences[UPDATE_CHANNEL],
                    selectedForBuildId = preferences[UPDATE_CHANNEL_BUILD_ID],
                    currentBuildId = updateChannelBuildId,
                    buildDefault = buildDefaultUpdateChannel,
                ),
                vpnHiding = VpnHidingOptions(
                    blockLocalEndpoints = preferences[VPN_HIDING_BLOCK_LOCAL_ENDPOINTS] ?: true,
                    neutralSessionName = preferences[VPN_HIDING_NEUTRAL_SESSION_NAME] ?: false,
                    tunMtuMode = preferences[VPN_HIDING_TUN_MTU_MODE]
                        ?.let { stored -> TunMtuMode.entries.firstOrNull { it.name == stored } }
                        ?: TunMtuMode.CoreDefault,
                ),
                onboardingCompleted = preferences[ONBOARDING_COMPLETED] ?: false,
                blockNonVpnTraffic = preferences[BLOCK_NON_VPN_TRAFFIC] ?: true,
                sortServersByPing = preferences[SORT_SERVERS_BY_PING] ?: true,
                powerMode = preferences[POWER_MODE]
                    ?.let { stored -> PowerMode.entries.firstOrNull { it.name == stored } }
                    ?: PowerMode.Balanced,
                serverMode = preferences[SERVER_MODE]
                    ?.let { stored -> ServerMode.entries.firstOrNull { it.name == stored } }
                    ?: ServerMode.Standard,
                autoConnectTrustedWifi = preferences[AUTO_CONNECT_TRUSTED_WIFI] ?: false,
                trustedWifiSsids = preferences[TRUSTED_WIFI_SSIDS].orEmpty(),
                reduceMotion = preferences[REDUCE_MOTION] ?: false,
                appLockEnabled = preferences[APP_LOCK_ENABLED] ?: true,
                notifyExitIpChange = preferences[NOTIFY_EXIT_IP_CHANGE] ?: true,
                compactHome = preferences[COMPACT_HOME] ?: false,
                beginnerMode = preferences[BEGINNER_MODE] ?: false,
                oledBlack = preferences[OLED_BLACK] ?: false,
                hideExitIp = preferences[HIDE_EXIT_IP] ?: false,
                flagSecure = preferences[FLAG_SECURE] ?: true,
                hapticsEnabled = preferences[HAPTICS_ENABLED] ?: true,
                showSessionTimer = preferences[SHOW_SESSION_TIMER] ?: true,
                autoFailoverEnabled = preferences[AUTO_FAILOVER] ?: true,
                idleRemindEnabled = preferences[IDLE_REMIND] ?: true,
                clearClipboardAfterImport = preferences[CLEAR_CLIPBOARD_AFTER_IMPORT] ?: true,
                muteNotificationTrafficDetail = preferences[MUTE_NOTIFICATION_TRAFFIC] ?: false,
                connectSoundEnabled = preferences[CONNECT_SOUND] ?: false,
                accentColor = preferences[ACCENT_COLOR]
                    ?.let { stored -> AccentColor.entries.firstOrNull { it.name == stored } }
                    ?: AccentColor.Green,
                largeText = preferences[LARGE_TEXT] ?: false,
                keepScreenOnWhileConnecting = preferences[KEEP_SCREEN_ON_CONNECTING] ?: false,
                confirmDisconnect = preferences[CONFIRM_DISCONNECT] ?: false,
                hideDeadServersDefault = preferences[HIDE_DEAD_DEFAULT] ?: false,
                autoPingOnServersOpen = preferences[AUTO_PING_SERVERS] ?: true,
                hideMap = preferences[HIDE_MAP] ?: false,
                homeVisualTheme = preferences[HOME_VISUAL_THEME]
                    ?.let { stored -> HomeVisualTheme.entries.firstOrNull { it.name == stored } }
                    ?: HomeVisualTheme.Globe3d,
                hideQuota = preferences[HIDE_QUOTA] ?: false,
                quietMode = preferences[QUIET_MODE] ?: false,
                homeLayoutMode = preferences[HOME_LAYOUT]
                    ?.let { stored -> HomeLayoutMode.entries.firstOrNull { it.name == stored } }
                    ?: HomeLayoutMode.Standard,
                confettiOnFirstConnect = preferences[CONFETTI_FIRST] ?: false,
                scheduleNightAutoConnect = preferences[SCHED_NIGHT] ?: false,
                scheduleMorningDisconnect = preferences[SCHED_MORNING] ?: false,
                autoLockOnDisconnect = preferences[AUTO_LOCK_DISC] ?: false,
                snoozeReconnectUntilEpochMillis = preferences[SNOOZE_RECONNECT]?.toLongOrNull() ?: 0L,
                lastSeenChangelogVersion = preferences[LAST_CHANGELOG].orEmpty(),
                biometricLockEnabled = preferences[BIOMETRIC_LOCK] ?: true,
                requireUnlockToDisconnect = preferences[UNLOCK_DISCONNECT] ?: false,
                requireUnlockToChangeServer = preferences[UNLOCK_CHANGE_SERVER] ?: false,
                highContrast = preferences[HIGH_CONTRAST] ?: false,
                useDynamicColor = preferences[USE_DYNAMIC_COLOR] ?: false,
                coachMarksDismissed = preferences[COACH_MARKS] ?: false,
                safeModeConnect = preferences[SAFE_MODE] ?: false,
                failoverCooldownUntilEpochMillis =
                    preferences[FAILOVER_COOLDOWN]?.toLongOrNull() ?: 0L,
                customDohUrl = preferences[CUSTOM_DOH_URL] ?: "",
                customDotUrl = preferences[CUSTOM_DOT_URL] ?: "",
                dismissedCoachMarkScreens = preferences[COACH_MARKS_SCREENS]
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.filter { it.isNotEmpty() }
                    ?.toSet()
                    ?: emptySet(),
                scheduleWorkConnect = preferences[SCHED_WORK] ?: false,
                skipAutoConnectWhenRoaming = preferences[SKIP_ROAMING] ?: true,
                autoConnectOnCellular = preferences[AUTO_CELLULAR] ?: false,
                timeRoutingEnabled = preferences[TIME_ROUTING] ?: false,
                tipsCarouselDismissed = preferences[TIPS_DISMISSED] ?: false,
                carrierBypassEnabled = preferences[CARRIER_BYPASS] ?: true,
                carrierBypassAlwaysAggressive = preferences[CARRIER_BYPASS_AGGRESSIVE] ?: true,
                bypassPreset = preferences[BYPASS_PRESET]
                    ?.let { stored ->
                        com.quantumvpn.hardening.BypassPreset.entries.firstOrNull { it.name == stored }
                    }
                    ?: if (preferences[CARRIER_BYPASS_AGGRESSIVE] == false) {
                        com.quantumvpn.hardening.BypassPreset.Soft
                    } else {
                        com.quantumvpn.hardening.BypassPreset.Tele2
                    },
                connectionExperienceMode = preferences[CONN_MODE]
                    ?.let { stored -> ConnectionExperienceMode.entries.firstOrNull { it.name == stored } }
                    ?: ConnectionExperienceMode.Normal,
                adBlockLevel = preferences[ADBLOCK_LEVEL]
                    ?.let { stored ->
                        com.quantumvpn.hardening.AdBlockLevel.entries.firstOrNull { it.name == stored }
                    }
                    ?: com.quantumvpn.hardening.AdBlockLevel.Maximum,
                adBlockEnabled = preferences[ADBLOCK_ENABLED] ?: true,
                adBlockOnlineDns = preferences[ADBLOCK_ONLINE_DNS] ?: true,
                adBlockTrackersOnly = preferences[ADBLOCK_TRACKERS_ONLY] ?: false,
                adBlockWhitelist = preferences[ADBLOCK_WHITELIST].orEmpty(),
                adBlockCategories = preferences[ADBLOCK_CATEGORIES]
                    ?.split(",")
                    ?.mapNotNull { name ->
                        com.quantumvpn.hardening.AdBlockCategory.entries
                            .firstOrNull { it.name == name }
                    }
                    ?.toSet()
                    ?: emptySet(),
                cumulativeBlocked = preferences[CUMULATIVE_BLOCKED]?.toLongOrNull() ?: 0L,
                softerBypassOnWifi = preferences[SOFTER_WIFI] ?: true,
                adaptiveDpiEnabled = preferences[ADAPTIVE_DPI] ?: true,
                connectFailStreak = preferences[CONNECT_FAIL_STREAK]?.toIntOrNull() ?: 0,
                incognitoSession = preferences[INCOGNITO] ?: false,
                homeBlocksOrder = preferences[HOME_BLOCKS]
                    ?: "modes,tools,server,subscription,adblock",
                subscriptionPriorityIds = preferences[SUB_PRIORITY].orEmpty(),
                subscriptionRefreshHours = preferences[SUB_REFRESH_H]?.toIntOrNull()
                    ?.takeIf { it > 0 }
                    ?: 6,
                lastSpeedTestDetail = preferences[LAST_SPEED].orEmpty(),
                blockWebRtcMdns = preferences[BLOCK_WEBRTC] ?: true,
                quietNightReconnect = preferences[QUIET_NIGHT] ?: true,
                qoeMonitorEnabled = preferences[QOE_MONITOR] ?: true,
                stealthUntilEpochMillis = preferences[STEALTH_UNTIL]?.toLongOrNull() ?: 0L,
                stealthMode = preferences[STEALTH_MODE] ?: true,
            )
        }

    suspend fun setThemeMode(mode: ThemeMode) {
        dataStore.edit { it[THEME_MODE] = mode.name }
    }

    suspend fun setActiveProfile(id: String?) {
        dataStore.edit { preferences ->
            if (id == null) preferences.remove(ACTIVE_PROFILE_ID)
            else preferences[ACTIVE_PROFILE_ID] = id
        }
    }

    suspend fun setRawEditorLineWrap(enabled: Boolean) {
        dataStore.edit { it[RAW_EDITOR_LINE_WRAP] = enabled }
    }

    suspend fun setDnsMode(mode: DnsMode) {
        dataStore.edit { it[DNS_MODE] = mode.name }
    }

    suspend fun setProxyIpv4Only(enabled: Boolean) {
        dataStore.edit { it[PROXY_IPV4_ONLY] = enabled }
    }

    suspend fun setDnsOverrideEnabled(enabled: Boolean) {
        dataStore.edit { it[DNS_OVERRIDE_ENABLED] = enabled }
    }

    suspend fun setDnsOverride(hostname: String, ipv4Address: String) {
        val normalized = requireNotNull(DnsOverride.normalizedOrNull(hostname, ipv4Address)) {
            "Invalid DNS override"
        }
        dataStore.edit {
            it[DNS_OVERRIDE_HOSTNAME] = normalized.hostname
            it[DNS_OVERRIDE_IPV4] = normalized.ipv4Address
        }
    }

    suspend fun setUpdateChannel(channel: UpdateChannel) {
        dataStore.edit {
            it[UPDATE_CHANNEL] = channel.name
            it[UPDATE_CHANNEL_BUILD_ID] = updateChannelBuildId
        }
    }

    suspend fun setVpnHidingBlockLocalEndpoints(enabled: Boolean) {
        dataStore.edit { it[VPN_HIDING_BLOCK_LOCAL_ENDPOINTS] = enabled }
    }

    suspend fun setVpnHidingNeutralSessionName(enabled: Boolean) {
        dataStore.edit { it[VPN_HIDING_NEUTRAL_SESSION_NAME] = enabled }
    }

    suspend fun setVpnHidingTunMtuMode(mode: TunMtuMode) {
        dataStore.edit { it[VPN_HIDING_TUN_MTU_MODE] = mode.name }
    }

    suspend fun setOnboardingCompleted(completed: Boolean) {
        dataStore.edit { it[ONBOARDING_COMPLETED] = completed }
    }

    suspend fun setBlockNonVpnTraffic(enabled: Boolean) {
        dataStore.edit { it[BLOCK_NON_VPN_TRAFFIC] = enabled }
    }

    suspend fun setSortServersByPing(enabled: Boolean) {
        dataStore.edit { it[SORT_SERVERS_BY_PING] = enabled }
    }

    suspend fun setPowerMode(mode: PowerMode) {
        dataStore.edit { preferences ->
            preferences[POWER_MODE] = mode.name
        }
    }

    suspend fun setServerMode(mode: ServerMode) {
        dataStore.edit { preferences ->
            preferences[SERVER_MODE] = mode.name
        }
    }

    suspend fun setAutoConnectTrustedWifi(enabled: Boolean) {
        dataStore.edit { it[AUTO_CONNECT_TRUSTED_WIFI] = enabled }
    }

    suspend fun setTrustedWifiSsids(raw: String) {
        dataStore.edit { it[TRUSTED_WIFI_SSIDS] = raw }
    }

    suspend fun setReduceMotion(enabled: Boolean) {
        dataStore.edit { it[REDUCE_MOTION] = enabled }
    }

    suspend fun setAppLockEnabled(enabled: Boolean) {
        dataStore.edit { it[APP_LOCK_ENABLED] = enabled }
    }

    suspend fun setNotifyExitIpChange(enabled: Boolean) {
        dataStore.edit { it[NOTIFY_EXIT_IP_CHANGE] = enabled }
    }

    suspend fun setCompactHome(enabled: Boolean) {
        dataStore.edit { it[COMPACT_HOME] = enabled }
    }

    suspend fun setBeginnerMode(enabled: Boolean) {
        dataStore.edit { it[BEGINNER_MODE] = enabled }
    }

    suspend fun setOledBlack(enabled: Boolean) {
        dataStore.edit { it[OLED_BLACK] = enabled }
    }

    suspend fun setHideExitIp(enabled: Boolean) {
        dataStore.edit { it[HIDE_EXIT_IP] = enabled }
    }

    suspend fun setFlagSecure(enabled: Boolean) {
        dataStore.edit { it[FLAG_SECURE] = enabled }
    }

    suspend fun setHapticsEnabled(enabled: Boolean) {
        dataStore.edit { it[HAPTICS_ENABLED] = enabled }
    }

    suspend fun setShowSessionTimer(enabled: Boolean) {
        dataStore.edit { it[SHOW_SESSION_TIMER] = enabled }
    }

    suspend fun setAutoFailoverEnabled(enabled: Boolean) {
        dataStore.edit { it[AUTO_FAILOVER] = enabled }
    }

    suspend fun setIdleRemindEnabled(enabled: Boolean) {
        dataStore.edit { it[IDLE_REMIND] = enabled }
    }

    suspend fun setClearClipboardAfterImport(enabled: Boolean) {
        dataStore.edit { it[CLEAR_CLIPBOARD_AFTER_IMPORT] = enabled }
    }

    suspend fun setMuteNotificationTrafficDetail(enabled: Boolean) {
        dataStore.edit { it[MUTE_NOTIFICATION_TRAFFIC] = enabled }
    }

    suspend fun setConnectSoundEnabled(enabled: Boolean) {
        dataStore.edit { it[CONNECT_SOUND] = enabled }
    }

    suspend fun setAccentColor(color: AccentColor) {
        dataStore.edit { it[ACCENT_COLOR] = color.name }
    }

    suspend fun setLargeText(enabled: Boolean) {
        dataStore.edit { it[LARGE_TEXT] = enabled }
    }

    suspend fun setKeepScreenOnWhileConnecting(enabled: Boolean) {
        dataStore.edit { it[KEEP_SCREEN_ON_CONNECTING] = enabled }
    }

    suspend fun setConfirmDisconnect(enabled: Boolean) {
        dataStore.edit { it[CONFIRM_DISCONNECT] = enabled }
    }

    suspend fun setHideDeadServersDefault(enabled: Boolean) {
        dataStore.edit { it[HIDE_DEAD_DEFAULT] = enabled }
    }

    suspend fun setAutoPingOnServersOpen(enabled: Boolean) {
        dataStore.edit { it[AUTO_PING_SERVERS] = enabled }
    }

    suspend fun setHideMap(enabled: Boolean) {
        dataStore.edit { it[HIDE_MAP] = enabled }
    }

    suspend fun setHomeVisualTheme(theme: HomeVisualTheme) {
        dataStore.edit { it[HOME_VISUAL_THEME] = theme.name }
    }

    suspend fun setHideQuota(enabled: Boolean) {
        dataStore.edit { it[HIDE_QUOTA] = enabled }
    }

    suspend fun setQuietMode(enabled: Boolean) {
        dataStore.edit { it[QUIET_MODE] = enabled }
    }

    suspend fun setHomeLayoutMode(mode: HomeLayoutMode) {
        dataStore.edit { it[HOME_LAYOUT] = mode.name }
    }

    suspend fun setConfettiOnFirstConnect(enabled: Boolean) {
        dataStore.edit { it[CONFETTI_FIRST] = enabled }
    }

    suspend fun setScheduleNightAutoConnect(enabled: Boolean) {
        dataStore.edit { it[SCHED_NIGHT] = enabled }
    }

    suspend fun setScheduleMorningDisconnect(enabled: Boolean) {
        dataStore.edit { it[SCHED_MORNING] = enabled }
    }

    suspend fun setAutoLockOnDisconnect(enabled: Boolean) {
        dataStore.edit { it[AUTO_LOCK_DISC] = enabled }
    }

    suspend fun setSnoozeReconnectUntil(epochMillis: Long) {
        dataStore.edit { it[SNOOZE_RECONNECT] = epochMillis.toString() }
    }

    suspend fun setLastSeenChangelogVersion(version: String) {
        dataStore.edit { it[LAST_CHANGELOG] = version }
    }

    suspend fun setBiometricLockEnabled(enabled: Boolean) {
        dataStore.edit { it[BIOMETRIC_LOCK] = enabled }
    }

    suspend fun setRequireUnlockToDisconnect(enabled: Boolean) {
        dataStore.edit { it[UNLOCK_DISCONNECT] = enabled }
    }

    suspend fun setRequireUnlockToChangeServer(enabled: Boolean) {
        dataStore.edit { it[UNLOCK_CHANGE_SERVER] = enabled }
    }

    suspend fun setHighContrast(enabled: Boolean) {
        dataStore.edit { it[HIGH_CONTRAST] = enabled }
    }

    suspend fun setUseDynamicColor(enabled: Boolean) {
        dataStore.edit { it[USE_DYNAMIC_COLOR] = enabled }
    }

    suspend fun setCoachMarksDismissed(dismissed: Boolean) {
        dataStore.edit { it[COACH_MARKS] = dismissed }
    }

    suspend fun dismissCoachMark(screen: CoachMarkScreen) {
        dataStore.edit { prefs ->
            val current = prefs[COACH_MARKS_SCREENS]
                ?.split(",")
                ?.map { it.trim() }
                ?.filter { it.isNotEmpty() }
                ?.toMutableSet()
                ?: mutableSetOf()
            current += screen.name
            prefs[COACH_MARKS_SCREENS] = current.joinToString(",")
            if (current.size >= CoachMarkScreen.entries.size) {
                prefs[COACH_MARKS] = true
            }
        }
    }

    suspend fun setCustomDohUrl(url: String) {
        dataStore.edit { it[CUSTOM_DOH_URL] = url.trim() }
    }

    suspend fun setCustomDotUrl(url: String) {
        dataStore.edit { it[CUSTOM_DOT_URL] = url.trim() }
    }

    suspend fun setSafeModeConnect(enabled: Boolean) {
        dataStore.edit { it[SAFE_MODE] = enabled }
    }

    suspend fun setFailoverCooldownUntil(epochMillis: Long) {
        dataStore.edit { it[FAILOVER_COOLDOWN] = epochMillis.toString() }
    }

    suspend fun setScheduleWorkConnect(enabled: Boolean) {
        dataStore.edit { it[SCHED_WORK] = enabled }
    }

    suspend fun setSkipAutoConnectWhenRoaming(enabled: Boolean) {
        dataStore.edit { it[SKIP_ROAMING] = enabled }
    }

    suspend fun setAutoConnectOnCellular(enabled: Boolean) {
        dataStore.edit { it[AUTO_CELLULAR] = enabled }
    }

    suspend fun setTimeRoutingEnabled(enabled: Boolean) {
        dataStore.edit { it[TIME_ROUTING] = enabled }
    }

    suspend fun setTipsCarouselDismissed(dismissed: Boolean) {
        dataStore.edit { it[TIPS_DISMISSED] = dismissed }
    }

    suspend fun setCarrierBypassEnabled(enabled: Boolean) {
        // DPI bypass is always on for all carriers; ignore disable requests.
        dataStore.edit { it[CARRIER_BYPASS] = true }
    }

    suspend fun setCarrierBypassAlwaysAggressive(enabled: Boolean) {
        dataStore.edit {
            it[CARRIER_BYPASS_AGGRESSIVE] = enabled
            val current = it[BYPASS_PRESET]
            if (enabled) {
                if (current == null ||
                    current == com.quantumvpn.hardening.BypassPreset.Soft.name ||
                    current == com.quantumvpn.hardening.BypassPreset.Standard.name
                ) {
                    it[BYPASS_PRESET] = com.quantumvpn.hardening.BypassPreset.Aggressive.name
                }
            } else if (current == com.quantumvpn.hardening.BypassPreset.Aggressive.name) {
                it[BYPASS_PRESET] = com.quantumvpn.hardening.BypassPreset.Standard.name
            }
        }
    }

    suspend fun setBypassPreset(preset: com.quantumvpn.hardening.BypassPreset) {
        dataStore.edit {
            it[BYPASS_PRESET] = preset.name
            // Selecting any preset turns DPI bypass back on.
            it[CARRIER_BYPASS] = true
            // Operator / Aggressive always arm reinforced (усиленный) mode.
            it[CARRIER_BYPASS_AGGRESSIVE] =
                preset == com.quantumvpn.hardening.BypassPreset.Tele2 ||
                    preset == com.quantumvpn.hardening.BypassPreset.Aggressive ||
                    preset == com.quantumvpn.hardening.BypassPreset.Standard
        }
    }

    suspend fun setConnectionExperienceMode(mode: ConnectionExperienceMode) {
        dataStore.edit { it[CONN_MODE] = mode.name }
    }

    suspend fun setAdBlockLevel(level: com.quantumvpn.hardening.AdBlockLevel) {
        dataStore.edit { it[ADBLOCK_LEVEL] = level.name }
    }

    suspend fun setAdBlockEnabled(enabled: Boolean) {
        dataStore.edit { it[ADBLOCK_ENABLED] = enabled }
    }

    suspend fun setAdBlockOnlineDns(enabled: Boolean) {
        dataStore.edit { it[ADBLOCK_ONLINE_DNS] = enabled }
    }

    suspend fun setAdBlockTrackersOnly(enabled: Boolean) {
        dataStore.edit { it[ADBLOCK_TRACKERS_ONLY] = enabled }
    }

    suspend fun setAdBlockWhitelist(raw: String) {
        dataStore.edit { it[ADBLOCK_WHITELIST] = raw.trim().take(2_000) }
    }

    suspend fun setAdBlockCategories(categories: Set<com.quantumvpn.hardening.AdBlockCategory>) {
        dataStore.edit { it[ADBLOCK_CATEGORIES] = categories.joinToString(",") { it.name } }
    }

    suspend fun addCumulativeBlocked(delta: Long) {
        if (delta <= 0) return
        dataStore.edit { prefs ->
            val current = prefs[CUMULATIVE_BLOCKED]?.toLongOrNull() ?: 0L
            prefs[CUMULATIVE_BLOCKED] = (current + delta).coerceAtLeast(0).toString()
        }
    }

    suspend fun setSofterBypassOnWifi(enabled: Boolean) {
        dataStore.edit { it[SOFTER_WIFI] = enabled }
    }

    suspend fun setAdaptiveDpiEnabled(enabled: Boolean) {
        dataStore.edit { it[ADAPTIVE_DPI] = enabled }
    }

    suspend fun setConnectFailStreak(streak: Int) {
        dataStore.edit { it[CONNECT_FAIL_STREAK] = streak.coerceIn(0, 99).toString() }
    }

    suspend fun setIncognitoSession(enabled: Boolean) {
        dataStore.edit { it[INCOGNITO] = enabled }
    }

    suspend fun setHomeBlocksOrder(order: String) {
        dataStore.edit { it[HOME_BLOCKS] = order.take(200) }
    }

    suspend fun setSubscriptionPriorityIds(csv: String) {
        dataStore.edit { it[SUB_PRIORITY] = csv.take(4_000) }
    }

    suspend fun setSubscriptionRefreshHours(hours: Int) {
        // Always-on: never allow disable; clamp 1..24h (default 6).
        dataStore.edit {
            it[SUB_REFRESH_H] = hours.coerceIn(1, 24).toString()
        }
    }

    suspend fun setLastSpeedTestDetail(detail: String) {
        dataStore.edit { it[LAST_SPEED] = detail.take(240) }
    }

    suspend fun setBlockWebRtcMdns(enabled: Boolean) {
        dataStore.edit { it[BLOCK_WEBRTC] = enabled }
    }

    suspend fun setQuietNightReconnect(enabled: Boolean) {
        dataStore.edit { it[QUIET_NIGHT] = enabled }
    }

    suspend fun setQoeMonitorEnabled(enabled: Boolean) {
        dataStore.edit { it[QOE_MONITOR] = enabled }
    }

    suspend fun setStealthUntilEpochMillis(epoch: Long) {
        dataStore.edit { it[STEALTH_UNTIL] = epoch.toString() }
    }

    suspend fun setStealthMode(enabled: Boolean) {
        dataStore.edit {
            it[STEALTH_MODE] = enabled
            // Stealth forces reinforced DPI obfuscation regardless of carrier.
            it[CARRIER_BYPASS] = true
            it[ADAPTIVE_DPI] = true
            if (enabled) {
                it[BYPASS_PRESET] = com.quantumvpn.hardening.BypassPreset.Aggressive.name
            }
        }
    }

    private companion object {
        val THEME_MODE = stringPreferencesKey("theme_mode")
        val ACTIVE_PROFILE_ID = stringPreferencesKey("active_profile_id")
        val RAW_EDITOR_LINE_WRAP = booleanPreferencesKey("raw_editor_line_wrap")
        val DNS_MODE = stringPreferencesKey("dns_mode")
        val PROXY_IPV4_ONLY = booleanPreferencesKey("proxy_ipv4_only")
        val DNS_OVERRIDE_ENABLED = booleanPreferencesKey("dns_override_enabled")
        val DNS_OVERRIDE_HOSTNAME = stringPreferencesKey("dns_override_hostname")
        val DNS_OVERRIDE_IPV4 = stringPreferencesKey("dns_override_ipv4")
        val UPDATE_CHANNEL = stringPreferencesKey("update_channel")
        val UPDATE_CHANNEL_BUILD_ID = stringPreferencesKey("update_channel_build_id")
        val VPN_HIDING_BLOCK_LOCAL_ENDPOINTS =
            booleanPreferencesKey("vpn_hiding_block_local_endpoints")
        val VPN_HIDING_NEUTRAL_SESSION_NAME =
            booleanPreferencesKey("vpn_hiding_neutral_session_name")
        val VPN_HIDING_TUN_MTU_MODE = stringPreferencesKey("vpn_hiding_tun_mtu_mode")
        val ONBOARDING_COMPLETED = booleanPreferencesKey("onboarding_completed")
        val BLOCK_NON_VPN_TRAFFIC = booleanPreferencesKey("block_non_vpn_traffic")
        val SORT_SERVERS_BY_PING = booleanPreferencesKey("sort_servers_by_ping")
        val POWER_MODE = stringPreferencesKey("power_mode")
        val SERVER_MODE = stringPreferencesKey("server_mode")
        val AUTO_CONNECT_TRUSTED_WIFI = booleanPreferencesKey("auto_connect_trusted_wifi")
        val TRUSTED_WIFI_SSIDS = stringPreferencesKey("trusted_wifi_ssids")
        val REDUCE_MOTION = booleanPreferencesKey("reduce_motion")
        val APP_LOCK_ENABLED = booleanPreferencesKey("app_lock_enabled")
        val NOTIFY_EXIT_IP_CHANGE = booleanPreferencesKey("notify_exit_ip_change")
        val COMPACT_HOME = booleanPreferencesKey("compact_home")
        val BEGINNER_MODE = booleanPreferencesKey("beginner_mode")
        val OLED_BLACK = booleanPreferencesKey("oled_black")
        val HIDE_EXIT_IP = booleanPreferencesKey("hide_exit_ip")
        val FLAG_SECURE = booleanPreferencesKey("flag_secure")
        val HAPTICS_ENABLED = booleanPreferencesKey("haptics_enabled")
        val SHOW_SESSION_TIMER = booleanPreferencesKey("show_session_timer")
        val AUTO_FAILOVER = booleanPreferencesKey("auto_failover")
        val IDLE_REMIND = booleanPreferencesKey("idle_remind")
        val CLEAR_CLIPBOARD_AFTER_IMPORT = booleanPreferencesKey("clear_clipboard_after_import")
        val MUTE_NOTIFICATION_TRAFFIC = booleanPreferencesKey("mute_notification_traffic")
        val CONNECT_SOUND = booleanPreferencesKey("connect_sound")
        val ACCENT_COLOR = stringPreferencesKey("accent_color")
        val LARGE_TEXT = booleanPreferencesKey("large_text")
        val KEEP_SCREEN_ON_CONNECTING = booleanPreferencesKey("keep_screen_on_connecting")
        val CONFIRM_DISCONNECT = booleanPreferencesKey("confirm_disconnect")
        val HIDE_DEAD_DEFAULT = booleanPreferencesKey("hide_dead_default")
        val AUTO_PING_SERVERS = booleanPreferencesKey("auto_ping_servers")
        val HIDE_MAP = booleanPreferencesKey("hide_map")
        val HOME_VISUAL_THEME = stringPreferencesKey("home_visual_theme")
        val HIDE_QUOTA = booleanPreferencesKey("hide_quota")
        val QUIET_MODE = booleanPreferencesKey("quiet_mode")
        val HOME_LAYOUT = stringPreferencesKey("home_layout")
        val CONFETTI_FIRST = booleanPreferencesKey("confetti_first")
        val SCHED_NIGHT = booleanPreferencesKey("sched_night")
        val SCHED_MORNING = booleanPreferencesKey("sched_morning")
        val AUTO_LOCK_DISC = booleanPreferencesKey("auto_lock_disc")
        val SNOOZE_RECONNECT = stringPreferencesKey("snooze_reconnect")
        val LAST_CHANGELOG = stringPreferencesKey("last_changelog")
        val BIOMETRIC_LOCK = booleanPreferencesKey("biometric_lock")
        val UNLOCK_DISCONNECT = booleanPreferencesKey("unlock_disconnect")
        val UNLOCK_CHANGE_SERVER = booleanPreferencesKey("unlock_change_server")
        val HIGH_CONTRAST = booleanPreferencesKey("high_contrast")
        val USE_DYNAMIC_COLOR = booleanPreferencesKey("use_dynamic_color")
        val COACH_MARKS = booleanPreferencesKey("coach_marks")
        val SAFE_MODE = booleanPreferencesKey("safe_mode")
        val FAILOVER_COOLDOWN = stringPreferencesKey("failover_cooldown")
        val CUSTOM_DOH_URL = stringPreferencesKey("custom_doh_url")
val CUSTOM_DOT_URL = stringPreferencesKey("custom_dot_url")
        val COACH_MARKS_SCREENS = stringPreferencesKey("coach_marks_screens")
        val SCHED_WORK = booleanPreferencesKey("sched_work")
        val SKIP_ROAMING = booleanPreferencesKey("skip_roaming")
        val AUTO_CELLULAR = booleanPreferencesKey("auto_cellular")
        val TIME_ROUTING = booleanPreferencesKey("time_routing")
        val TIPS_DISMISSED = booleanPreferencesKey("tips_dismissed")
        val CARRIER_BYPASS = booleanPreferencesKey("carrier_bypass")
        val CARRIER_BYPASS_AGGRESSIVE = booleanPreferencesKey("carrier_bypass_aggressive")
        val BYPASS_PRESET = stringPreferencesKey("bypass_preset")
        val CONN_MODE = stringPreferencesKey("conn_experience_mode")
        val ADBLOCK_LEVEL = stringPreferencesKey("adblock_level")
        val ADBLOCK_ENABLED = booleanPreferencesKey("adblock_enabled")
        val ADBLOCK_ONLINE_DNS = booleanPreferencesKey("adblock_online_dns")
        val ADBLOCK_TRACKERS_ONLY = booleanPreferencesKey("adblock_trackers_only")
        val ADBLOCK_WHITELIST = stringPreferencesKey("adblock_whitelist")
        val ADBLOCK_CATEGORIES = stringPreferencesKey("adblock_categories")
        val CUMULATIVE_BLOCKED = stringPreferencesKey("cumulative_blocked")
        val SOFTER_WIFI = booleanPreferencesKey("softer_bypass_wifi")
        val ADAPTIVE_DPI = booleanPreferencesKey("adaptive_dpi")
        val CONNECT_FAIL_STREAK = stringPreferencesKey("connect_fail_streak")
        val INCOGNITO = booleanPreferencesKey("incognito_session")
        val HOME_BLOCKS = stringPreferencesKey("home_blocks_order")
        val SUB_PRIORITY = stringPreferencesKey("sub_priority_ids")
        val SUB_REFRESH_H = stringPreferencesKey("sub_refresh_hours")
        val LAST_SPEED = stringPreferencesKey("last_speed_detail")
        val BLOCK_WEBRTC = booleanPreferencesKey("block_webrtc_mdns")
        val QUIET_NIGHT = booleanPreferencesKey("quiet_night_reconnect")
        val QOE_MONITOR = booleanPreferencesKey("qoe_monitor")
        val STEALTH_UNTIL = stringPreferencesKey("stealth_until")
        val STEALTH_MODE = booleanPreferencesKey("stealth_mode")
    }
}

internal fun resolveUpdateChannel(
    storedChannel: String?,
    selectedForBuildId: String?,
    currentBuildId: String,
    buildDefault: UpdateChannel,
): UpdateChannel {
    if (selectedForBuildId != currentBuildId) return buildDefault
    return storedChannel
        ?.let { stored -> UpdateChannel.entries.firstOrNull { it.name == stored } }
        ?: buildDefault
}
