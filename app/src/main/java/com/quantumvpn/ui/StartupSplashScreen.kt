package com.quantumvpn.ui

import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import com.quantumvpn.QuantumVpnApplication
import com.quantumvpn.routing.RoutingPolicyRefreshResult
import com.quantumvpn.updates.UpdateState
import com.quantumvpn.vpn.RuntimeOutboundItem
import com.quantumvpn.vpn.UnderlyingServerPing
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Validates startup data; does not apply profiles or start a VPN. */
@Composable
fun StartupSplashScreen(
    ready: Boolean, updateState: UpdateState, availableServers: Int, reduceMotion: Boolean = false,
    onFinished: () -> Unit, routingEnabled: Boolean = true, serverItems: List<RuntimeOutboundItem> = emptyList(),
) {
    val app = LocalContext.current.applicationContext as QuantumVpnApplication
    var rulesReady by remember(routingEnabled) { mutableStateOf(!routingEnabled) }
    var rulesDetail by remember(routingEnabled) { mutableStateOf(if (routingEnabled) "Проверяем подпись правил…" else "Маршрутизация выключена") }
    LaunchedEffect(routingEnabled) {
        if (!routingEnabled) return@LaunchedEffect
        val result = withContext(Dispatchers.IO) { app.container.remoteRoutingPolicyRepository.refresh() }
        rulesDetail = when (result) {
            is RoutingPolicyRefreshResult.Applied -> "Правила r${result.verified.policy.revision} · подпись проверена" + if (result.fromCache) " · сохранённая копия" else ""
            is RoutingPolicyRefreshResult.Unavailable -> "Правила панели недоступны · используем встроенные"
        }
        rulesReady = true
    }
    val serverProbeKey = serverItems.map { Triple(it.tag, it.type, it.endpoint) }
    // New targets must reset synchronously, before the finish effect can run.
    var serversChecked by remember(serverProbeKey) { mutableStateOf(serverItems.isEmpty()) }
    var reachable by remember(serverProbeKey) { mutableStateOf<Int?>(null) }
    LaunchedEffect(serverProbeKey) {
        if (serverItems.isEmpty()) { serversChecked = true; reachable = null; return@LaunchedEffect }
        serversChecked = false
        reachable = runCatching { UnderlyingServerPing.measure(app, serverItems.take(6)).size }.getOrDefault(0)
        serversChecked = true
    }
    ResourcePresentation(app.container.appResourceRepository) {
        AuroraStartup2026(ready, updateState, availableServers, reduceMotion,
            rulesReady = rulesReady, rulesDetail = rulesDetail, serversChecked = serversChecked,
            reachableServers = reachable, onFinished = onFinished)
    }
}
