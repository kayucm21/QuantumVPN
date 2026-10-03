package com.quantumvpn.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.quantumvpn.BuildConfig
import com.quantumvpn.updates.UpdateState

/** Only measured APK bytes produce a percentage. Startup checks have no fake progress. */
@Composable
internal fun AuroraStartup2026(
    ready: Boolean, update: UpdateState, servers: Int, reduceMotion: Boolean,
    rulesReady: Boolean = true, rulesDetail: String = "Локальные правила",
    serversChecked: Boolean = true, reachableServers: Int? = null,
    onFinished: () -> Unit,
) {
    val canFinish = startupFinishAllowed(ready, update) && rulesReady && serversChecked
    val latestOnFinished by rememberUpdatedState(onFinished)
    var handedOff by remember { mutableStateOf(false) }
    LaunchedEffect(canFinish) {
        if (canFinish && !handedOff) {
            handedOff = true
            latestOnFinished()
        }
    }
    val cyan = Color(0xFF2CEBF1)
    val muted = Color(0xFFABC0D4)
    val download = update as? UpdateState.Downloading
    val fraction = download?.let { startupDownloadProgress(it.downloadedBytes, it.totalBytes) }
    val updateSettled = startupFinishAllowed(true, update)
    val status = when (update) {
        is UpdateState.Downloading -> "Загружаем обновление ${update.candidate.metadata.versionName}"
        is UpdateState.Ready -> "Пакет проверен · подтвердите установку Android"
        is UpdateState.Available -> "Новая версия найдена · готовим загрузку"
        is UpdateState.Checking, is UpdateState.RetryingViaVpn -> "Проверяем обновления"
        is UpdateState.Failure -> "Не удалось проверить обновление · повторим позже"
        else -> if (!rulesReady) "Проверяем подписанные правила" else if (!serversChecked) "Проверяем доступность серверов" else "Приложение готово"
    }
    BoxWithConstraints(Modifier.fillMaxSize().background(Color(0xFF040B16))) {
        Quantum2Wallpaper(Modifier.fillMaxSize(), earth = true)
        Box(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Color(0x55040B16), Color.Transparent, Color(0xF0040B16)))))
        val compact = maxHeight < 650.dp
        Column(
            Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding()
                .verticalScroll(rememberScrollState()).padding(horizontal = 24.dp, vertical = 18.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text("Добро пожаловать", color = Color.White, fontSize = if (compact) 25.sp else 28.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(if (compact) 18.dp else 38.dp))
            AuroraBrandMark(false, Modifier.size(if (compact) 112.dp else 148.dp))
            Text(LocalAppResources.current?.text("brand_name", "QuantumVPN") ?: "QuantumVPN",
                color = Color.White, fontSize = 30.sp, fontWeight = FontWeight.Bold)
            Text("2.0", color = cyan, fontSize = 19.sp, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(if (compact) 44.dp else 74.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                StartupStage("Проверяем\nобновление", updateSettled, !updateSettled, cyan, Modifier.weight(1f))
                StartupStage("Загружаем\nправила", rulesReady, updateSettled && !rulesReady, cyan, Modifier.weight(1f))
                StartupStage("Проверяем\nсерверы", serversChecked, rulesReady && !serversChecked, cyan, Modifier.weight(1f))
            }
            Spacer(Modifier.height(20.dp))
            Text(status, color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, textAlign = TextAlign.Center)
            Spacer(Modifier.height(12.dp))
            if (download != null) {
                if (fraction != null) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        LinearProgressIndicator(progress = { fraction }, color = cyan, trackColor = Color(0xFF23415C),
                            modifier = Modifier.weight(1f).height(6.dp).semantics { contentDescription = "Загрузка ${(fraction * 100).toInt()} процентов" })
                        Text("${(fraction * 100).toInt()}%", color = Color.White, fontWeight = FontWeight.SemiBold)
                    }
                } else if (!reduceMotion) LinearProgressIndicator(color = cyan, trackColor = Color(0xFF23415C), modifier = Modifier.fillMaxWidth())
                Text(if (download.totalBytes > 0) "${formatBytes(download.downloadedBytes)} / ${formatBytes(download.totalBytes)}" else "Загружено ${formatBytes(download.downloadedBytes)}",
                    color = Color.White, fontSize = 13.sp, modifier = Modifier.padding(top = 12.dp))
                Text(buildString {
                    append(if (download.speedBytesPerSecond > 0) "${formatBytes(download.speedBytesPerSecond)}/с" else "Скорость уточняется")
                    append(" · ")
                    append(download.etaSeconds?.let { "осталось ${it.coerceAtLeast(1)} с" } ?: "время уточняется")
                }, color = muted, fontSize = 12.sp)
            } else {
                if (!canFinish && !reduceMotion && update !is UpdateState.Ready) {
                    LinearProgressIndicator(color = cyan, trackColor = Color(0xFF23415C), modifier = Modifier.fillMaxWidth())
                }
                Text(rulesDetail, color = muted, fontSize = 11.sp, modifier = Modifier.padding(top = 12.dp), textAlign = TextAlign.Center)
                Text(if (servers == 0) "Нет серверов в подписке · повторите проверку на главной"
                    else if (reachableServers != null) "Профилей: $servers · ответили на проверку: $reachableServers"
                    else "Профилей в подписке: $servers", color = muted, fontSize = 11.sp, textAlign = TextAlign.Center)
            }
            Spacer(Modifier.height(22.dp))
            Text("Версия ${BuildConfig.VERSION_NAME} · Quantum 2.0", color = muted, fontSize = 11.sp)
            if (download != null || update is UpdateState.Ready || update is UpdateState.Available) {
                Text("Установка — после вашего подтверждения в Android.", color = muted, fontSize = 11.sp, textAlign = TextAlign.Center)
            }
        }
    }
}

@Composable
private fun StartupStage(title: String, complete: Boolean, active: Boolean, accent: Color, modifier: Modifier) {
    Column(modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Surface(shape = CircleShape, color = if (active) accent.copy(alpha = .18f) else Color(0xFF081A2E),
            border = androidx.compose.foundation.BorderStroke(2.dp, if (complete || active) accent else Color(0xFF536A85)), modifier = Modifier.size(25.dp)) {
            Box(contentAlignment = Alignment.Center) {
                Text(if (complete) "✓" else if (active) "●" else "", color = accent, fontSize = 15.sp, fontWeight = FontWeight.Bold)
            }
        }
        Text(title, color = if (complete || active) Color.White else Color(0xFFABC0D4), fontSize = 11.sp,
            textAlign = TextAlign.Center, modifier = Modifier.padding(top = 10.dp))
    }
}
