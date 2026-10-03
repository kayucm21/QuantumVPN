package com.quantumvpn.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.quantumvpn.BuildConfig
import com.quantumvpn.updates.UpdateState

/** No simulated percentage: determinate progress belongs only to a known-size APK download. */
@Composable
internal fun AuroraStartup2026(ready: Boolean, update: UpdateState, servers: Int, reduceMotion: Boolean, onFinished: () -> Unit) {
    LaunchedEffect(ready) { if (ready) onFinished() }
    val mint = Color(0xFF58F4CE)
    val resources = LocalAppResources.current
    val muted = Color(0xFFABC0D4)
    val download = update as? UpdateState.Downloading
    val fraction = download?.let { startupDownloadProgress(it.downloadedBytes, it.totalBytes) }
    val updateSettled = update is UpdateState.UpToDate || update is UpdateState.Failure
    val status = when (update) {
        is UpdateState.Downloading -> "Загружаем обновление ${update.candidate.metadata.versionName}"
        is UpdateState.Ready -> "Пакет проверен · подтвердите установку Android"
        is UpdateState.Available -> "Новая версия найдена · готовим загрузку"
        is UpdateState.Checking, is UpdateState.RetryingViaVpn -> "Проверяем обновления"
        is UpdateState.Failure -> "Проверка обновления не завершена"
        else -> if (servers > 0) "Подготавливаем приложение" else "Загружаем список серверов"
    }
    Box(Modifier.fillMaxSize().background(Color(0xFF040B16))) {
        AuroraGlassBackdrop(Modifier.fillMaxSize(), motionEnabled = false)
        Column(
            Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().verticalScroll(rememberScrollState()).padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Spacer(Modifier.height(8.dp))
            AuroraBrandMark(ready, Modifier.size(64.dp))
            if (resources?.texts?.containsKey("brand_name") == true) {
                Text(resources.text("brand_name", "QuantumVPN"), color = Color.White, fontSize = 30.sp, fontWeight = FontWeight.Bold)
            } else Row {
                Text("Quantum", color = Color.White, fontSize = 30.sp, fontWeight = FontWeight.Bold)
                Text("VPN", color = mint, fontSize = 30.sp, fontWeight = FontWeight.Bold)
            }
            Text(resources?.text("welcome", "Больше свободы. Ближе к людям.") ?: "Больше свободы. Ближе к людям.", color = muted, fontSize = 14.sp)
            Spacer(Modifier.height(12.dp))
            AuroraConnectButton(connected = ready, busy = !ready, enabled = false, reduceMotion = reduceMotion, actionLabel = "Подготовка", compact = true, onClick = {})
            Text(status, color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 18.sp)
            AuroraGlass(Modifier.fillMaxWidth(), cornerRadius = 20.dp) {
                Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    if (download != null) {
                        Text(
                            if (download.totalBytes > 0) "${formatBytes(download.downloadedBytes)} / ${formatBytes(download.totalBytes)}" else "Загружено ${formatBytes(download.downloadedBytes)}",
                            color = Color.White,
                        )
                        if (fraction != null) {
                            LinearProgressIndicator(progress = { fraction }, color = mint, trackColor = Color(0xFF23415C), modifier = Modifier.fillMaxWidth().semantics { contentDescription = "Загрузка ${(fraction * 100).toInt()} процентов" })
                        } else if (!reduceMotion) {
                            LinearProgressIndicator(color = mint, modifier = Modifier.fillMaxWidth())
                        }
                        Text(
                            buildString {
                                append(if (download.speedBytesPerSecond > 0) "${formatBytes(download.speedBytesPerSecond)}/с" else "Скорость уточняется")
                                append(" · ")
                                append(download.etaSeconds?.let { "осталось ${it.coerceAtLeast(1)} с" } ?: "время уточняется")
                            }, color = muted, fontSize = 12.sp,
                        )
                    } else {
                        StartupCheckRow("Обновление", if (update is UpdateState.Failure) "Недоступно · попробуем позже" else if (updateSettled) "Проверено" else "Проверяем", update is UpdateState.UpToDate)
                        StartupCheckRow("Серверы", if (servers > 0) "Доступно профилей: $servers" else "Получаем подписку", servers > 0)
                        StartupCheckRow("Приложение", if (ready) "Готово" else "Подготовка", ready)
                    }
                }
            }
            Text("Версия ${BuildConfig.VERSION_NAME} · Aurora 2026", color = muted, fontSize = 12.sp)
            Text("Обновление устанавливается только после вашего подтверждения в Android.", color = muted, fontSize = 12.sp)
        }
    }
}

@Composable
private fun StartupCheckRow(title: String, detail: String, complete: Boolean) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(if (complete) "✓" else "○", color = Color(0xFF58F4CE), fontSize = 20.sp)
        Column(Modifier.padding(start = 12.dp)) {
            Text(title, color = Color.White, fontWeight = FontWeight.SemiBold)
            Text(detail, color = Color(0xFFABC0D4), fontSize = 12.sp)
        }
    }
}
