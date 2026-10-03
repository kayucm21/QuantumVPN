package com.quantumvpn.ui

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.quantumvpn.resources.AppResourceRepository
import com.quantumvpn.resources.AppResources
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

internal val LocalAppResources = staticCompositionLocalOf<AppResources?> { null }
internal val LocalResourceLogo = staticCompositionLocalOf<Bitmap?> { null }

@Composable
internal fun ResourcePresentation(repository: AppResourceRepository, content: @Composable () -> Unit) {
    val resources by repository.resources.collectAsState()
    val logo by produceState<Bitmap?>(null, resources?.assets?.get("logo")?.sha256) {
        value = withContext(Dispatchers.IO) {
            runCatching { repository.imageFile("logo")?.let { BitmapFactory.decodeFile(it.absolutePath) } }.getOrNull()
        }
    }
    CompositionLocalProvider(LocalAppResources provides resources, LocalResourceLogo provides logo, content = content)
}

@Composable
internal fun ResourceStatusDialog(repository: AppResourceRepository, onDismiss: () -> Unit) {
    val status by repository.status.collectAsState()
    val resources by repository.resources.collectAsState()
    val scope = rememberCoroutineScope()
    var checking by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Ресурсы приложения") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(status)
                Text(resources?.let { "Ревизия r${it.revision} · публикация ${it.sequence}" } ?: "Используется встроенное оформление")
                Text("Ed25519 + SHA-256. Тексты, цвет, фон и логотип обновляются из панели. Личный фон сохраняется; VPN-движок и код не меняются.")
            }
        },
        confirmButton = { TextButton(enabled = !checking, onClick = {
            checking = true
            scope.launch { try { repository.refresh(force = true) } finally { checking = false } }
        }, modifier = Modifier.heightIn(min = 48.dp)) { Text(if (checking) "Проверяем…" else "Проверить") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Закрыть") } },
    )
}
