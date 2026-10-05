package com.quantumvpn.community

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject

/** Root supplies navigation and an optional explicit-consent diagnostic snapshot. */
@Composable
fun SupportCenterScreen(
    modifier: Modifier = Modifier,
    onBack: () -> Unit,
    onOpenInbox: () -> Unit = {},
    diagnosticProvider: (() -> JSONObject)? = null,
    networkEnabled: Boolean = true,
    initialThreads: List<SupportThread> = emptyList(),
    initialThread: SupportThread? = null,
) {
    val context = LocalContext.current
    val repository = remember(context) { CommunityRepository(context) }
    val scope = rememberCoroutineScope()
    var threads by remember { mutableStateOf(initialThreads) }
    var selected by remember { mutableStateOf(initialThread) }
    var subject by rememberSaveable { mutableStateOf("") }
    var message by rememberSaveable { mutableStateOf("") }
    var attachDiagnostic by rememberSaveable { mutableStateOf(false) }
    var requestId by rememberSaveable { mutableStateOf(UUID.randomUUID().toString()) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf("") }
    var qualityConsent by remember { mutableStateOf(repository.qualityConsent()) }

    suspend fun reload() {
        if (!networkEnabled) return
        repository.threads().onSuccess { threads = it }.onFailure { error = it.message.orEmpty() }
    }

    LaunchedEffect(repository) {
        if (!networkEnabled) return@LaunchedEffect
        busy = true
        reload()
        busy = false
    }
    // Only the conversation currently visible on screen is polled. Disposing
    // this composable cancels the effect; no background timer/service exists.
    LaunchedEffect(selected?.id) {
        if (!networkEnabled) return@LaunchedEffect
        val id = selected?.id ?: return@LaunchedEffect
        while (isActive) {
            delay(15_000)
            if (busy || selected?.state != "open") continue
            repository.thread(id).onSuccess { selected = it }
        }
    }

    LazyColumn(modifier.fillMaxSize().testTag("support-center"),
        contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item("header") {
            Column {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    TextButton(onClick = { if (selected != null) selected = null else onBack() }) { Text("Назад") }
                    TextButton(onClick = onOpenInbox) { Text("Уведомления") }
                }
                Text(selected?.let { "Обращение #${it.id}" } ?: "Поддержка QuantumVPN", style = MaterialTheme.typography.headlineSmall)
                Text("Ответ администратора останется в приложении и в ленте уведомлений.", style = MaterialTheme.typography.bodyMedium)
            }
        }
        if (error.isNotBlank()) item("error") {
            Text(error, color = MaterialTheme.colorScheme.error, modifier = Modifier.testTag("support-error"))
        }
        if (busy) item("busy") { CircularProgressIndicator() }
        selected?.let { thread ->
            item("thread-title") {
                Text(thread.subject, style = MaterialTheme.typography.titleLarge)
                Text(if (thread.state == "open") "Открыто · ожидаем ответ" else "Обращение закрыто")
            }
            items(thread.messages, key = { "message:${it.id}" }) { entry ->
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(if (entry.sender == "operator") "Поддержка" else "Вы", style = MaterialTheme.typography.labelLarge,
                            color = if (entry.sender == "operator") MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
                        Text(entry.body)
                        Text(communityDate(entry.createdAtSeconds), style = MaterialTheme.typography.labelSmall)
                        if (entry.hasDiagnostic) Text("Прикреплена обезличенная диагностика", style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
        }
        if (selected == null || selected?.state == "open") item("composer") {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    if (selected == null) OutlinedTextField(subject, { subject = it.take(120) },
                        label = { Text("Тема") }, singleLine = true, enabled = !busy,
                        modifier = Modifier.fillMaxWidth().testTag("support-subject"))
                    OutlinedTextField(message, { message = it.take(4_000) }, label = { Text("Сообщение") },
                        minLines = 3, maxLines = 8, enabled = !busy,
                        modifier = Modifier.fillMaxWidth().testTag("support-message"))
                    if (selected == null && diagnosticProvider != null) Row {
                        Checkbox(attachDiagnostic, { attachDiagnostic = it }, enabled = !busy)
                        Text("Разрешаю отправить обезличенную диагностику. Пароли и подписки не отправляются.",
                            style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 10.dp))
                    }
                    Button(onClick = {
                        if (busy) return@Button
                        busy = true
                        error = ""
                        scope.launch {
                            try {
                                val current = selected
                                val result = if (current == null) repository.createSupport(subject, message,
                                    diagnostic = if (attachDiagnostic) diagnosticProvider?.invoke() else null,
                                    diagnosticConsent = attachDiagnostic, requestId = requestId)
                                else repository.sendMessage(current.id, message, requestId)
                                result.onSuccess {
                                    selected = it
                                    message = ""
                                    subject = ""
                                    attachDiagnostic = false
                                    requestId = UUID.randomUUID().toString()
                                    reload()
                                }.onFailure { error = it.message.orEmpty() }
                            } catch (problem: Exception) {
                                error = problem.message ?: "Не удалось подготовить сообщение"
                            } finally {
                                busy = false
                            }
                        }
                    }, enabled = networkEnabled && !busy && message.isNotBlank() && (selected != null || subject.isNotBlank()),
                        modifier = Modifier.fillMaxWidth().testTag("support-send")) {
                        Text(if (selected == null) "Отправить обращение" else "Отправить сообщение")
                    }
                    Text("При ошибке текст сохраняется. Повторная отправка не создаст дубликат.", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        if (selected == null) {
            item("quality") {
                Card(Modifier.fillMaxWidth()) {
                    Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Column(Modifier.weight(1f)) {
                            Text("Помочь улучшить стабильность", style = MaterialTheme.typography.titleSmall)
                            Text("Только показатели соединения: протокол, тип сети, задержка и обрывы. Без истории сайтов. Можно выключить в любой момент.", style = MaterialTheme.typography.bodySmall)
                        }
                        Switch(qualityConsent, { qualityConsent = it; repository.setQualityConsent(it) }, enabled = networkEnabled, modifier = Modifier.testTag("quality-consent"))
                    }
                }
            }
            item("threads-header") {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Мои обращения", style = MaterialTheme.typography.titleMedium)
                    TextButton(onClick = { scope.launch { reload() } }, enabled = networkEnabled && !busy) { Text("Обновить") }
                }
                if (threads.isEmpty() && !busy) Text("Обращений пока нет. Опишите проблему выше.")
            }
            items(threads, key = { "thread:${it.id}" }) { thread ->
                OutlinedButton(onClick = {
                    if (!networkEnabled) { selected = thread; return@OutlinedButton }
                    busy = true
                    error = ""
                    scope.launch {
                        repository.thread(thread.id).onSuccess { selected = it }.onFailure { error = it.message.orEmpty() }
                        busy = false
                    }
                }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.fillMaxWidth()) {
                        Text("#${thread.id} · ${thread.subject}")
                        Text(if (thread.state == "open") "Открыто" else "Закрыто", style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
        }
    }
}

@Composable
fun NotificationInboxScreen(
    modifier: Modifier = Modifier,
    onBack: () -> Unit,
    onOpenSupport: () -> Unit = {},
    networkEnabled: Boolean = true,
    initialEntries: List<InboxEntry>? = null,
) {
    val context = LocalContext.current
    val repository = remember(context) { CommunityRepository(context) }
    val scope = rememberCoroutineScope()
    var entries by remember { mutableStateOf(initialEntries ?: repository.cachedInbox()) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf("") }
    suspend fun refresh() {
        if (!networkEnabled) return
        busy = true
        error = ""
        try {
            repository.refreshInbox().onSuccess { entries = it }.onFailure {
                error = "Нет связи с панелью. Сохранённые уведомления доступны."
            }
        } finally { busy = false }
    }
    LaunchedEffect(repository) { refresh() }
    LazyColumn(modifier.fillMaxSize().testTag("notification-inbox"), contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item("header") {
            TextButton(onClick = onBack) { Text("Назад") }
            Text("Уведомления", style = MaterialTheme.typography.headlineSmall)
            Text("Обновления, технические работы, восстановление сервиса и ответы поддержки — в одной ленте.")
            Row {
                TextButton(onClick = { scope.launch { refresh() } }, enabled = networkEnabled && !busy) { Text("Обновить") }
                TextButton(onClick = {
                    if (!networkEnabled) { entries = entries.map { it.copy(read = true) }; return@TextButton }
                    scope.launch { repository.markInboxRead().onSuccess { entries = it }.onFailure { entries = repository.cachedInbox() } }
                }, enabled = entries.any { !it.read }) { Text("Прочитать все") }
            }
        }
        if (error.isNotBlank()) item("offline") { Text(error, color = MaterialTheme.colorScheme.onSurfaceVariant) }
        if (busy) item("busy") { CircularProgressIndicator() }
        if (entries.isEmpty() && !busy) item("empty") { Text("Новых уведомлений пока нет.") }
        items(entries, key = { it.key }) { entry ->
            Card(Modifier.fillMaxWidth().testTag("inbox-${entry.kind}")) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                    Text((if (!entry.read) "● " else "") + entry.title, style = MaterialTheme.typography.titleMedium,
                        color = if (!entry.read) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface)
                    Text(entry.body, style = MaterialTheme.typography.bodyMedium)
                    Text(communityDate(entry.createdAtSeconds), style = MaterialTheme.typography.labelSmall)
                    if (entry.kind == "support_reply") TextButton(onClick = onOpenSupport) { Text("Открыть поддержку") }
                }
            }
        }
    }
}

private fun communityDate(seconds: Long): String = SimpleDateFormat("dd.MM · HH:mm", Locale.getDefault()).format(Date(seconds * 1_000))
