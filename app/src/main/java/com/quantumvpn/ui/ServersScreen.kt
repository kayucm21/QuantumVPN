package com.quantumvpn.ui

import android.content.Context
import android.net.ConnectivityManager
import com.quantumvpn.networkbootstrap.networksCompat
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import com.quantumvpn.vpn.DeadServerQuarantineStore
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.quantumvpn.config.ConfigAnalyzer
import com.quantumvpn.profiles.ProfileMetadata
import com.quantumvpn.profiles.ProfileStore
import com.quantumvpn.vpn.ExitLocationResolver
import com.quantumvpn.vpn.FavoriteServersStore
import com.quantumvpn.vpn.IcmpPingProbe
import com.quantumvpn.vpn.RuntimeOutboundItem
import com.quantumvpn.vpn.RuntimeSelectorGroup
import com.quantumvpn.vpn.ServerPingTarget
import com.quantumvpn.vpn.SessionPingCache
import com.quantumvpn.vpn.ServerHealthScore
import com.quantumvpn.vpn.VpnConnectionState
import com.quantumvpn.vpn.forServerUi
import com.quantumvpn.vpn.primaryGroup
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext

@OptIn(ExperimentalFoundationApi::class, ExperimentalMaterial3Api::class)
@Composable
internal fun ServersScreen(
    contentPadding: PaddingValues,
    profiles: List<ProfileMetadata>,
    activeProfile: ProfileMetadata?,
    selectorGroups: List<RuntimeSelectorGroup>,
    profileSelectorGroups: List<RuntimeSelectorGroup>,
    vpnState: VpnConnectionState,
    profileStore: ProfileStore,
    onSelectProfile: (String) -> Unit,
    onAddProfile: () -> Unit,
    onSelectServer: (groupTag: String, outboundTag: String) -> Unit,
    onSelectOutboundLive: (profileId: String, groupTag: String, outboundTag: String) -> Unit,
    onMeasureGroupLive: (String) -> Unit,
    sortByPing: Boolean = true,
    favoriteKeys: Set<String> = emptySet(),
    pinnedKeys: List<String> = emptyList(),
    onToggleFavorite: (profileId: String, groupTag: String, outboundTag: String) -> Unit = { _, _, _ -> },
    onTogglePin: (profileId: String, groupTag: String, outboundTag: String) -> Unit = { _, _, _ -> },
    switchHistory: List<com.quantumvpn.vpn.ServerSwitchEvent> = emptyList(),
    serverNotes: Map<String, String> = emptyMap(),
    onSetServerNote: (profileId: String, groupTag: String, outboundTag: String, note: String) -> Unit =
        { _, _, _, _ -> },
    hideDeadDefault: Boolean = false,
    autoPingOnOpen: Boolean = true,
    quarantinedKeys: Set<String> = emptySet(),
    showCoachMark: Boolean = false,
    onDismissCoachMark: () -> Unit = {},
    onRefreshSubscriptions: () -> Unit = {},
    onRecordProbeFailure: (profileId: String, groupTag: String, outboundTag: String) -> Unit = { _, _, _ -> },
    onRecordProbeSuccess: (profileId: String, groupTag: String, outboundTag: String) -> Unit = { _, _, _ -> },
    reliabilityScores: Map<String, Int> = emptyMap(),
    reliabilityEntries: Map<String, com.quantumvpn.vpn.ReliabilityEntry> = emptyMap(),
    serverMode: com.quantumvpn.ui.ServerMode = com.quantumvpn.ui.ServerMode.Standard,
    compactActions: Boolean = false,
) {
    val connected = vpnState as? VpnConnectionState.Connected
    val displayGroups = when {
        connected != null && selectorGroups.any { it.items.isNotEmpty() } -> selectorGroups
        profileSelectorGroups.any { it.items.isNotEmpty() } -> profileSelectorGroups
        else -> selectorGroups
    }.forServerUi()
    val primary = displayGroups.primaryGroup()
    val servers = primary?.items.orEmpty()
    var pinging by remember { mutableStateOf(false) }
    var offlinePings by remember { mutableStateOf<Map<String, Int?>>(emptyMap()) }
    var query by remember { mutableStateOf("") }
    var countryFilter by remember { mutableStateOf<String?>(null) }
    var protocolFilter by remember { mutableStateOf<String?>(null) }
    var favoritesOnly by remember { mutableStateOf(false) }
    var liveOnly by remember { mutableStateOf(false) }
    var hideDead by remember { mutableStateOf(hideDeadDefault) }
    var noteTarget by remember { mutableStateOf<RuntimeOutboundItem?>(null) }
    var noteDraft by remember { mutableStateOf("") }
    var maxPingFilter by remember { mutableStateOf<Int?>(null) }
    var sortByName by remember { mutableStateOf(false) }
    var compareA by remember { mutableStateOf<String?>(null) }
    var compareB by remember { mutableStateOf<String?>(null) }
    var compareC by remember { mutableStateOf<String?>(null) }
    var compareMode by remember { mutableStateOf(false) }
    var detailTag by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val profileId = activeProfile?.id

    LaunchedEffect(profileId) {
        if (profileId != null) {
            SessionPingCache.bind(profileId)
            offlinePings = SessionPingCache.snapshot()
        }
    }

    fun pingOf(item: RuntimeOutboundItem): Int? =
        item.pingMillis ?: offlinePings[item.tag] ?: SessionPingCache.get(item.tag)

    fun isFav(tag: String): Boolean =
        profileId != null && primary != null &&
            FavoriteServersStore.key(profileId, primary.tag, tag) in favoriteKeys

    fun isPinned(tag: String): Boolean =
        profileId != null && primary != null &&
            FavoriteServersStore.key(profileId, primary.tag, tag) in pinnedKeys

    fun protocolOf(item: RuntimeOutboundItem): String =
        item.type.ifBlank { "unknown" }.lowercase()

    val filtered = servers.filter { item ->
        val country = ExitLocationResolver.fromServerLabel(item.tag)?.countryName ?: "Другие"
        val matchesQuery = query.isBlank() ||
            item.tag.contains(query, ignoreCase = true) ||
            item.type.contains(query, ignoreCase = true) ||
            (item.endpoint?.contains(query, ignoreCase = true) == true)
        val matchesCountry = countryFilter == null || country == countryFilter
        val matchesProtocol = protocolFilter == null || protocolOf(item) == protocolFilter
        val matchesFav = !favoritesOnly || isFav(item.tag)
        val matchesLive = !liveOnly || pingOf(item) != null
        val ping = pingOf(item)
        val matchesDead = !hideDead || (ping != null && ping < 2_000)
        val serverKey = if (profileId != null && primary != null) {
            DeadServerQuarantineStore.serverKey(profileId, primary.tag, item.tag)
        } else {
            ""
        }
        val matchesQuarantine = serverKey.isBlank() || serverKey !in quarantinedKeys
        val matchesMax = maxPingFilter == null || (ping != null && ping <= maxPingFilter!!)
        matchesQuery && matchesCountry && matchesProtocol && matchesFav && matchesLive &&
            matchesDead && matchesQuarantine && matchesMax
    }

    val orderedServers = if (sortByName) {
        filtered.sortedBy { it.tag.lowercase() }
    } else if (!sortByPing) {
        filtered
    } else {
        filtered.sortedWith(
            compareBy<RuntimeOutboundItem> {
                val key = if (profileId != null && primary != null) {
                    FavoriteServersStore.key(profileId, primary.tag, it.tag)
                } else {
                    ""
                }
                key !in pinnedKeys
            }
                .thenBy { !isFav(it.tag) }
                .thenBy { pingOf(it) == null }
                .thenBy { pingOf(it) ?: Int.MAX_VALUE }
                .thenBy { it.tag },
        )
    }
    val countrySections = orderedServers
        .groupBy { item ->
            ExitLocationResolver.fromServerLabel(item.tag)?.countryName ?: "Другие"
        }
        .toList()
        .sortedBy { (name, _) -> if (name == "Другие") "я" else name }
    val allCountries = servers.map {
        ExitLocationResolver.fromServerLabel(it.tag)?.countryName ?: "Другие"
    }.distinct().sorted()
    val allProtocols = servers.map(::protocolOf).distinct().sorted()

    fun runPing() {
        if (primary == null || servers.isEmpty()) {
            if (activeProfile == null) onAddProfile()
            return
        }
        if (pinging) return
        pinging = true
        val group = primary
        if (connected != null) {
            onMeasureGroupLive(group.tag)
        }
        if (activeProfile != null) {
            scope.launch {
                val result = runCatching {
                    measureOfflinePings(
                        context = context,
                        profileStore = profileStore,
                        profileId = activeProfile.id,
                        group = group,
                    )
                }.getOrDefault(emptyMap())
                SessionPingCache.putAll(activeProfile.id, result)
                offlinePings = offlinePings + result
                if (primary != null) {
                    result.forEach { (tag, ping) ->
                        if (ping == null || ping >= 2_000) {
                            onRecordProbeFailure(activeProfile.id, primary.tag, tag)
                        } else {
                            onRecordProbeSuccess(activeProfile.id, primary.tag, tag)
                        }
                    }
                }
                pinging = false
            }
        } else {
            pinging = false
        }
    }

    var autoPingDone by remember(profileId) { mutableStateOf(false) }
    LaunchedEffect(profileId, servers.size, offlinePings.isEmpty(), autoPingOnOpen) {
        if (autoPingOnOpen &&
            profileId != null &&
            servers.isNotEmpty() &&
            !autoPingDone &&
            offlinePings.isEmpty() &&
            !pinging
        ) {
            autoPingDone = true
            runPing()
        }
    }

    fun selectSameRegion() {
        val currentCountry = servers
            .firstOrNull { it.tag == primary?.selected }
            ?.let { ExitLocationResolver.fromServerLabel(it.tag)?.countryCode }
            ?: return
        val best = orderedServers
            .filter {
                ExitLocationResolver.fromServerLabel(it.tag)?.countryCode == currentCountry
            }
            .mapNotNull { item -> pingOf(item)?.let { item to it } }
            .minByOrNull { it.second }
            ?.first
        if (best != null && primary != null) {
            if (connected != null) {
                onSelectOutboundLive(connected.profileId, primary.tag, best.tag)
            } else {
                onSelectServer(primary.tag, best.tag)
            }
        }
    }

    fun selectBestPing() {
        val best = orderedServers
            .mapNotNull { item -> pingOf(item)?.let { item to it } }
            .minByOrNull { it.second }
            ?.first
        if (best != null && primary != null) {
            if (connected != null) {
                onSelectOutboundLive(connected.profileId, primary.tag, best.tag)
            } else {
                onSelectServer(primary.tag, best.tag)
            }
        } else {
            runPing()
        }
    }

    fun selectNightFriendly() {
        val hour = java.util.Calendar.getInstance().get(java.util.Calendar.HOUR_OF_DAY)
        val nightish = hour >= 22 || hour < 7
        val scored = orderedServers.map { item ->
            val label = item.tag.lowercase()
            val bonus = when {
                "night" in label || "nl" in label || "de" in label || "fi" in label -> 40
                "game" in label || "stream" in label -> 10
                else -> 0
            }
            val ping = pingOf(item) ?: 9999
            item to (ping - if (nightish) bonus else bonus / 2)
        }
        val best = scored.minByOrNull { it.second }?.first
        if (best != null && primary != null) {
            if (connected != null) {
                onSelectOutboundLive(connected.profileId, primary.tag, best.tag)
            } else {
                onSelectServer(primary.tag, best.tag)
            }
        } else {
            runPing()
        }
    }

    fun selectRandomServer() {
        val pool = orderedServers.ifEmpty { servers }
        val pick = pool.randomOrNull() ?: return
        if (primary == null) return
        if (connected != null) {
            onSelectOutboundLive(connected.profileId, primary.tag, pick.tag)
        } else {
            onSelectServer(primary.tag, pick.tag)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(contentPadding)
            .padding(horizontal = 16.dp),
    ) {
        if (showCoachMark) {
            CoachMarkBanner(
                screen = CoachMarkScreen.Servers,
                onDismiss = onDismissCoachMark,
                modifier = Modifier.padding(bottom = 8.dp),
            )
        }

        if (activeProfile == null) {
            EmptyState(
                title = "Нет подписки",
                body = "Импортируйте ссылку или файл — серверы появятся здесь.",
                actionLabel = "Добавить подписку",
                onAction = onAddProfile,
                icon = EmptyStateIcons.NoSubscription,
            )
            return
        }

        Text(
            activeProfile.name,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(bottom = 8.dp),
        )

        if (profiles.size > 1) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
            ) {
                profiles.take(6).forEach { profile ->
                    val selected = profile.id == activeProfile.id
                    FilterChip(
                        selected = selected,
                        onClick = { onSelectProfile(profile.id) },
                        enabled = vpnState is VpnConnectionState.Stopped ||
                            vpnState is VpnConnectionState.Error,
                        label = {
                            Text(
                                profile.name,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        },
                    )
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
        }

        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text("Поиск") },
            placeholder = { Text("Имя, страна, протокол") },
        )
        Spacer(modifier = Modifier.height(8.dp))
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(
                selected = favoritesOnly,
                onClick = { favoritesOnly = !favoritesOnly },
                label = { Text("Избранные") },
            )
            FilterChip(
                selected = liveOnly,
                onClick = { liveOnly = !liveOnly },
                label = { Text("С пингом") },
            )
            FilterChip(
                selected = hideDead,
                onClick = { hideDead = !hideDead },
                label = { Text("Скрыть мёртвые") },
            )
            FilterChip(
                selected = sortByName,
                onClick = { sortByName = !sortByName },
                label = { Text("По имени") },
            )
            FilterChip(
                selected = maxPingFilter == null,
                onClick = { maxPingFilter = null },
                label = { Text("Любой пинг") },
            )
            listOf(50, 100, 200).forEach { limit ->
                FilterChip(
                    selected = maxPingFilter == limit,
                    onClick = {
                        maxPingFilter = if (maxPingFilter == limit) null else limit
                    },
                    label = { Text("<$limit ms") },
                )
            }
            FilterChip(
                selected = compareMode,
                onClick = {
                    compareMode = !compareMode
                    if (!compareMode) {
                        compareA = null
                        compareB = null
                        compareC = null
                    }
                },
                label = { Text("Сравнить") },
            )
            FilterChip(
                selected = protocolFilter == null,
                onClick = { protocolFilter = null },
                label = { Text("Все протоколы") },
            )
            allProtocols.forEach { proto ->
                FilterChip(
                    selected = protocolFilter == proto,
                    onClick = {
                        protocolFilter = if (protocolFilter == proto) null else proto
                    },
                    label = { Text(proto) },
                )
            }
            FilterChip(
                selected = countryFilter == null,
                onClick = { countryFilter = null },
                label = { Text("Все страны") },
            )
            allCountries.forEach { country ->
                FilterChip(
                    selected = countryFilter == country,
                    onClick = {
                        countryFilter = if (countryFilter == country) null else country
                    },
                    label = { Text(country) },
                )
            }
        }
        Spacer(modifier = Modifier.height(8.dp))
        if (compareMode && (compareA != null || compareB != null || compareC != null)) {
            val a = servers.firstOrNull { it.tag == compareA }
            val b = servers.firstOrNull { it.tag == compareB }
            val c = servers.firstOrNull { it.tag == compareC }
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
                shape = MaterialTheme.shapes.medium,
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.7f),
            ) {
                Text("Сравнение 3 серверов", fontWeight = FontWeight.SemiBold)
                Text(
                    "A: ${a?.tag ?: "—"} · " +
                        (a?.let(::pingOf)?.let { "$it ms" } ?: "нет пинга"),
                )
                Text(
                    "B: ${b?.tag ?: "—"} · " +
                        (b?.let(::pingOf)?.let { "$it ms" } ?: "нет пинга"),
                )
                Text(
                    "C: ${c?.tag ?: "—"} · " +
                        (c?.let(::pingOf)?.let { "$it ms" } ?: "нет пинга"),
                )
                val ranked = listOfNotNull(
                    a?.let { it to pingOf(it) },
                    b?.let { it to pingOf(it) },
                    c?.let { it to pingOf(it) },
                ).mapNotNull { (item, ping) -> ping?.let { item to it } }
                    .sortedBy { it.second }
                ranked.firstOrNull()?.let { (best, ping) ->
                    Text(
                        "Лучший: ${best.tag} ($ping ms)",
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Button(
                onClick = ::runPing,
                enabled = !pinging && servers.isNotEmpty(),
                modifier = Modifier.weight(1f),
            ) {
                if (pinging) {
                    CircularProgressIndicator(
                        modifier = Modifier
                            .padding(end = 8.dp)
                            .height(18.dp),
                        strokeWidth = 2.dp,
                    )
                }
                Text(if (servers.isEmpty()) "Добавить" else "Пинг")
            }
            OutlinedButton(
                onClick = ::selectBestPing,
                enabled = !pinging && servers.isNotEmpty(),
                modifier = Modifier.weight(1f),
            ) {
                Text("Лучший пинг")
            }
        }
        Spacer(modifier = Modifier.height(8.dp))
        if (!compactActions) {
            OutlinedButton(
                onClick = ::selectSameRegion,
                enabled = !pinging && servers.isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Тот же регион")
            }
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(
                onClick = ::selectNightFriendly,
                enabled = !pinging && servers.isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Ночной / стабильный выбор")
            }
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(
                onClick = ::selectRandomServer,
                enabled = servers.isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Случайный сервер")
            }
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(
                onClick = {
                    val csv = buildString {
                        appendLine("tag,type,ping_ms,endpoint")
                        orderedServers.forEach { item ->
                            val ping = pingOf(item)?.toString().orEmpty()
                            val endpoint = item.endpoint.orEmpty().replace(',', ';')
                            appendLine("${item.tag},${item.type},$ping,$endpoint")
                        }
                    }
                    val send = android.content.Intent(android.content.Intent.ACTION_SEND)
                        .setType("text/csv")
                        .putExtra(android.content.Intent.EXTRA_SUBJECT, "QuantumVPN pings")
                        .putExtra(android.content.Intent.EXTRA_TEXT, csv)
                    context.startActivity(android.content.Intent.createChooser(send, "Экспорт пингов"))
                },
                enabled = orderedServers.isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Экспорт пингов CSV")
            }
            Spacer(modifier = Modifier.height(8.dp))
        }
        OutlinedButton(
            onClick = onAddProfile,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (compactActions) "Подписки" else "Управление подписками")
        }

        if (switchHistory.isNotEmpty()) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                "Недавние смены",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
            switchHistory.take(5).forEach { event ->
                Text(
                    "${event.outboundTag}${event.countryCode?.let { " · $it" }.orEmpty()}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        if (servers.isEmpty()) {
            EmptyState(
                title = "Нет серверов",
                body = "В этой подписке нет узлов для выбора. Обновите подписку или добавьте другую.",
                actionLabel = "Управление подписками",
                onAction = onAddProfile,
                icon = EmptyStateIcons.NoServers,
            )
        } else if (orderedServers.isEmpty()) {
            Text(
                "Нет серверов по фильтрам.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            val recommended = remember(orderedServers, primary?.selected, offlinePings, reliabilityScores) {
                val regionCode = orderedServers.firstOrNull { it.tag == primary?.selected }
                    ?.let { ExitLocationResolver.fromServerLabel(it.tag)?.countryCode }
                orderedServers
                    .mapNotNull { item ->
                        val ping = pingOf(item)
                        val key = if (profileId != null && primary != null) {
                            DeadServerQuarantineStore.serverKey(profileId, primary.tag, item.tag)
                        } else {
                            null
                        }
                        val score = key?.let { reliabilityScores[it] } ?: 50
                        if (ping != null) item to (ping - score / 10) else null
                    }
                    .filter { (item, _) ->
                        regionCode == null ||
                            ExitLocationResolver.fromServerLabel(item.tag)?.countryCode == regionCode
                    }
                    .minByOrNull { it.second }
                    ?.first
            }
            var refreshing by remember { mutableStateOf(false) }
            @OptIn(ExperimentalMaterial3Api::class)
            PullToRefreshBox(
                isRefreshing = refreshing,
                onRefresh = {
                    refreshing = true
                    onRefreshSubscriptions()
                    refreshing = false
                },
                modifier = Modifier.weight(1f),
            ) {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                    contentPadding = PaddingValues(bottom = 24.dp),
                ) {
                    item(key = "servers-summary") {
                        val best = orderedServers
                            .mapNotNull { item -> pingOf(item)?.let { item to it } }
                            .minByOrNull { it.second }
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            color = CosmicTokens.VipBlue.copy(alpha = 0.92f),
                            shape = MaterialTheme.shapes.large,
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Text(
                                        "Серверы · ${orderedServers.size}",
                                        color = Color.White,
                                        fontWeight = FontWeight.Bold,
                                    )
                                    if (serverMode != com.quantumvpn.ui.ServerMode.Standard) {
                                        Surface(
                                            color = Color.White.copy(alpha = 0.18f),
                                            shape = MaterialTheme.shapes.small,
                                        ) {
                                            Text(
                                                when (serverMode) {
                                                    com.quantumvpn.ui.ServerMode.Gaming -> "🎮 Gaming"
                                                    com.quantumvpn.ui.ServerMode.Movie -> "🎬 Movie"
                                                    com.quantumvpn.ui.ServerMode.Standard -> ""
                                                },
                                                color = Color.White,
                                                style = MaterialTheme.typography.labelSmall,
                                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                                            )
                                        }
                                    }
                                }
                                Text(
                                    best?.let { "Лучший пинг: ${it.second} ms · ${it.first.tag}" }
                                        ?: "Потяните вниз или нажмите «Проверить» для пинга",
                                    color = Color.White.copy(alpha = 0.85f),
                                    style = MaterialTheme.typography.bodySmall,
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                        }
                    }
                    recommended?.let { pick ->
                        item(key = "recommended") {
                            Surface(
                                modifier = Modifier.fillMaxWidth(),
                                color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.5f),
                                shape = MaterialTheme.shapes.large,
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            "Рекомендовано",
                                            style = MaterialTheme.typography.labelMedium,
                                            color = MaterialTheme.colorScheme.primary,
                                        )
                                        Text(
                                            pick.tag,
                                            fontWeight = FontWeight.SemiBold,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                        )
                                        pingOf(pick)?.let { Text("$it ms", style = MaterialTheme.typography.bodySmall) }
                                    }
                                    TextButton(
                                        onClick = {
                                            if (connected != null) {
                                                onSelectOutboundLive(connected.profileId, primary!!.tag, pick.tag)
                                            } else {
                                                onSelectServer(primary!!.tag, pick.tag)
                                            }
                                        },
                                    ) { Text("Выбрать") }
                                }
                            }
                        }
                    }
                    val ranked = orderedServers
                        .mapNotNull { item ->
                            reliabilityEntries[item.tag]?.let { entry ->
                                Triple(item, entry, reliabilityScores[item.tag] ?: entry.score)
                            }
                        }
                        .filter { it.second.successes + it.second.failures >= 2 }
                        .sortedByDescending { it.third }
                        .take(5)
                    if (ranked.isNotEmpty()) {
                        item(key = "reliability-ranking") {
                            Surface(
                                modifier = Modifier.fillMaxWidth(),
                                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
                                shape = MaterialTheme.shapes.large,
                            ) {
                                Column(
                                    modifier = Modifier.padding(14.dp),
                                    verticalArrangement = Arrangement.spacedBy(6.dp),
                                ) {
                                    Text(
                                        "Надёжность серверов",
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.SemiBold,
                                    )
                                    ranked.forEachIndexed { index, (item, entry, score) ->
                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically,
                                        ) {
                                            Text(
                                                "${index + 1}. ${item.tag}",
                                                style = MaterialTheme.typography.bodySmall,
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis,
                                                modifier = Modifier.weight(1f),
                                            )
                                            Text(
                                                "$score% · ${entry.successes}✓/${entry.failures}✗",
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                    countrySections.forEach { (country, sectionServers) ->
                        stickyHeader(key = "sticky-$country") {
                            Text(
                                country,
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.primary,
                                fontWeight = FontWeight.SemiBold,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(top = 4.dp, bottom = 2.dp),
                            )
                        }
                        items(sectionServers, key = { it.tag }) { item ->
                        val selected = primary?.selected == item.tag
                        val ping = pingOf(item)
                        val loc = ExitLocationResolver.fromServerLabel(item.tag)
                        val countryName = loc?.countryName ?: country
                        val city = serverCityHint(item.tag, countryName)
                        Surface(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    if (compareMode) {
                                        when {
                                            compareA == null || compareA == item.tag -> compareA = item.tag
                                            compareB == null || compareB == item.tag -> compareB = item.tag
                                            compareC == null || compareC == item.tag -> compareC = item.tag
                                            else -> {
                                                compareA = compareB
                                                compareB = compareC
                                                compareC = item.tag
                                            }
                                        }
                                    } else if (connected != null) {
                                        onSelectOutboundLive(connected.profileId, primary!!.tag, item.tag)
                                    } else {
                                        onSelectServer(primary!!.tag, item.tag)
                                    }
                                },
                            color = if (selected) {
                                CosmicTokens.Card.copy(alpha = 0.95f)
                            } else {
                                CosmicTokens.Card.copy(alpha = 0.72f)
                            },
                            shape = MaterialTheme.shapes.large,
                            border = if (selected) {
                                androidx.compose.foundation.BorderStroke(1.dp, CosmicTokens.Orbit.copy(alpha = 0.7f))
                            } else {
                                null
                            },
                        ) {
                            Row(
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 14.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                RadioButton(
                                    selected = selected,
                                    onClick = {
                                        if (connected != null) {
                                            onSelectOutboundLive(connected.profileId, primary!!.tag, item.tag)
                                        } else {
                                            onSelectServer(primary!!.tag, item.tag)
                                        }
                                    },
                                )
                                Text(
                                    loc?.flagEmoji ?: "🌐",
                                    style = MaterialTheme.typography.headlineSmall,
                                    modifier = Modifier.padding(end = 10.dp),
                                )
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        countryName,
                                        fontWeight = FontWeight.SemiBold,
                                        color = Color.White,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                    Text(
                                        city.ifBlank { item.type.ifBlank { "Сервер" } },
                                        style = MaterialTheme.typography.bodySmall,
                                        color = Color.White.copy(alpha = 0.6f),
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                }
                                Column(horizontalAlignment = Alignment.End) {
                                    SignalBars(pingMillis = ping)
                                    Text(
                                        speedLabelRu(ping),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = PingColors.themedColor(ping),
                                        maxLines = 1,
                                    )
                                }
                            }
                        }
                    }
                }
            }
            }
        }
    }

    detailTag?.let { tag ->
        val item = servers.firstOrNull { it.tag == tag }
        if (item != null) {
            AlertDialog(
                onDismissRequest = { detailTag = null },
                title = { Text(item.tag) },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("Протокол: ${item.type}")
                        Text("Пинг: ${pingOf(item)?.let { "$it ms" } ?: "—"}")
                        Text("Endpoint: ${item.endpoint ?: "—"}")
                        Text(
                            "Страна: " +
                                (ExitLocationResolver.fromServerLabel(item.tag)?.countryName ?: "—"),
                        )
                        Text("Избранное: ${if (isFav(item.tag)) "да" else "нет"}")
                    }
                },
                confirmButton = {
                    TextButton(onClick = { detailTag = null }) { Text("OK") }
                },
                dismissButton = {
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        TextButton(
                            onClick = {
                                val country = ExitLocationResolver.fromServerLabel(item.tag)?.countryName
                                val ping = pingOf(item)
                                val share = buildString {
                                    append("QuantumVPN server: ").append(item.tag)
                                    country?.let { append(" · ").append(it) }
                                    ping?.let { append(" · ").append(it).append(" ms") }
                                }
                                val intent = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                                    type = "text/plain"
                                    putExtra(android.content.Intent.EXTRA_TEXT, share)
                                }
                                context.startActivity(
                                    android.content.Intent.createChooser(intent, "Поделиться сервером"),
                                )
                            },
                        ) { Text("Share") }
                        TextButton(
                            onClick = {
                                val cm = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE)
                                    as android.content.ClipboardManager
                                cm.setPrimaryClip(
                                    android.content.ClipData.newPlainText("server", item.tag),
                                )
                                detailTag = null
                            },
                        ) { Text("Копировать тег") }
                    }
                },
            )
        }
    }
    val editing = noteTarget
    if (editing != null && activeProfile != null && primary != null) {
        AlertDialog(
            onDismissRequest = { noteTarget = null },
            title = { Text("Заметка") },
            text = {
                OutlinedTextField(
                    value = noteDraft,
                    onValueChange = { noteDraft = it.take(120) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    placeholder = { Text("Например: дом / работа") },
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        onSetServerNote(activeProfile.id, primary.tag, editing.tag, noteDraft)
                        noteTarget = null
                    },
                ) { Text("Сохранить") }
            },
            dismissButton = {
                TextButton(onClick = { noteTarget = null }) { Text("Отмена") }
            },
        )
    }
}

internal suspend fun measureOfflinePings(
    context: Context,
    profileStore: ProfileStore,
    profileId: String,
    group: RuntimeSelectorGroup,
): Map<String, Int?> = withContext(Dispatchers.IO) {
    val connectivity = context.getSystemService(ConnectivityManager::class.java)
    val network = preferredPingNetwork(connectivity)
        ?: error("Нет активной сети Android для ICMP.")
    val descriptions = ConfigAnalyzer.outboundDescriptions(profileStore.read(profileId).json)
    val probe = IcmpPingProbe()
    val concurrency = Semaphore(4)
    coroutineScope {
        group.items.map { item ->
            async {
                concurrency.withPermit {
                    val host = descriptions[item.tag]?.serverHost
                    val ping = if (host.isNullOrBlank()) {
                        null
                    } else {
                        runCatching {
                            probe.measure(network, ServerPingTarget(item.tag, host)).toInt()
                        }.getOrNull()
                    }
                    item.tag to ping
                }
            }
        }.awaitAll()
    }.toMap()
}

@Composable
private fun SignalBars(pingMillis: Int?) {
    val level = when {
        pingMillis == null -> 0
        pingMillis < 80 -> 4
        pingMillis < 150 -> 3
        pingMillis < 250 -> 2
        else -> 1
    }
    val active = when (level) {
        4 -> CosmicTokens.StatusGreen
        3 -> CosmicTokens.StatusGreen.copy(alpha = 0.85f)
        2 -> CosmicTokens.StatusYellow
        1 -> MaterialTheme.colorScheme.error
        else -> Color.White.copy(alpha = 0.25f)
    }
    Canvas(modifier = Modifier.size(width = 22.dp, height = 16.dp)) {
        val gap = 2.dp.toPx()
        val barW = (size.width - gap * 3) / 4f
        for (i in 0 until 4) {
            val h = size.height * ((i + 1) / 4f)
            val on = i < level
            drawRoundRect(
                color = if (on) active else Color.White.copy(alpha = 0.2f),
                topLeft = Offset(i * (barW + gap), size.height - h),
                size = Size(barW, h),
                cornerRadius = CornerRadius(1.5.dp.toPx(), 1.5.dp.toPx()),
            )
        }
    }
}

private fun speedLabelRu(pingMillis: Int?): String = when {
    pingMillis == null -> "Нет пинга"
    pingMillis < 80 -> "Быстрый"
    pingMillis < 150 -> "Нормальный"
    pingMillis < 250 -> "Средний"
    else -> "Медленный"
}

private fun serverCityHint(tag: String, countryName: String): String {
    val cleaned = tag
        .replace(Regex("""[\p{So}\p{Cn}]+"""), " ")
        .replace(countryName, "", ignoreCase = true)
        .replace(Regex("""\b(vless|vmess|trojan|ss|hysteria2?|reality|wg|wireguard)\b""", RegexOption.IGNORE_CASE), "")
        .replace(Regex("""[#_|\\-]+"""), " ")
        .replace(Regex("""\s+"""), " ")
        .trim()
    return cleaned.take(40)
}

private fun preferredPingNetwork(connectivity: ConnectivityManager): android.net.Network? {
    val candidates = connectivity.networksCompat.filter { network ->
        val caps = connectivity.getNetworkCapabilities(network) ?: return@filter false
        if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) return@filter false
        caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }
    return candidates.firstOrNull { network ->
        val caps = connectivity.getNetworkCapabilities(network) ?: return@firstOrNull false
        caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) ||
            caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR) ||
            caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET)
    } ?: candidates.firstOrNull() ?: connectivity.activeNetwork
}
