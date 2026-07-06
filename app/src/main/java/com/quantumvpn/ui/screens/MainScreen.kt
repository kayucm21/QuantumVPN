package com.quantumvpn.ui.screens

import android.Manifest
import android.app.Activity
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import com.quantumvpn.data.*
import com.quantumvpn.viewmodel.MainViewModel
import kotlin.math.cos
import kotlin.math.sin

@Composable
fun MainScreen(viewModel: MainViewModel = viewModel()) {
    val context = LocalContext.current
    val vpnState by viewModel.vpnState.collectAsState()
    val servers by viewModel.servers.collectAsState()
    val error by viewModel.error.collectAsState()
    val selectedProtocol by viewModel.selectedProtocol.collectAsState()
    val showAddDialog by viewModel.showAddSubscription.collectAsState()

    var showSettings by remember { mutableStateOf(false) }
    var vpnPermOk by remember { mutableStateOf(false) }
    var notifPermOk by remember { mutableStateOf(false) }

    val vpnLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        vpnPermOk = r.resultCode == Activity.RESULT_OK
        if (vpnPermOk) viewModel.connectVPN()
    }
    val notifLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { notifPermOk = it }

    LaunchedEffect(Unit) {
        vpnPermOk = VpnService.prepare(context) == null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notifPermOk = ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        } else notifPermOk = true
    }
    LaunchedEffect(vpnState.isConnecting) {
        if (vpnState.isConnecting && !vpnPermOk) {
            VpnService.prepare(context)?.let { vpnLauncher.launch(it) }
        }
    }
    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !notifPermOk) {
            notifLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    Box(modifier = Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Color(0xFF0D0B2E), Color(0xFF1A1145), Color(0xFF0D0B2E))))) {
        LazyColumn(modifier = Modifier.fillMaxSize(), contentPadding = PaddingValues(bottom = 100.dp)) {
            // Top bar
            item {
                Row(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 12.dp), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = { showSettings = true }) { Icon(Icons.Outlined.Settings, "Настройки", tint = Color.White.copy(0.7f)) }
                    Row {
                        IconButton(onClick = { importFromClipboard(context, viewModel) }) { Icon(Icons.Outlined.ContentPaste, "Из буфера", tint = Color(0xFF7C6CFF)) }
                        IconButton(onClick = { viewModel.showAddSubscription(true) }) { Icon(Icons.Filled.Add, "Добавить", tint = Color.White) }
                    }
                }
            }

            // Brand
            item {
                Text("кому ключи?", Modifier.fillMaxWidth(), textAlign = TextAlign.Center, fontSize = 22.sp, fontWeight = FontWeight.Bold, color = Color.White)
                Spacer(Modifier.height(4.dp))
                Text("нажми, чтобы подключить", Modifier.fillMaxWidth(), textAlign = TextAlign.Center, fontSize = 13.sp, color = Color.White.copy(0.5f))
            }

            // Power button
            item {
                Box(Modifier.fillMaxWidth().padding(vertical = 20.dp), contentAlignment = Alignment.Center) {
                    PowerButton(vpnState.isConnected, vpnState.isConnecting) {
                        if (!vpnPermOk) VpnService.prepare(context)?.let { vpnLauncher.launch(it) }
                        else viewModel.toggleConnection()
                    }
                }
            }

            // Traffic display
            if (vpnState.isConnected) {
                item {
                    Card(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 4.dp), RoundedCornerShape(14.dp), colors = CardDefaults.cardColors(Color.White.copy(0.06f))) {
                        Row(Modifier.fillMaxWidth().padding(16.dp), horizontalArrangement = Arrangement.SpaceEvenly) {
                            TrafficCol("↓ Загрузка", formatBytes(vpnState.totalDownload))
                            TrafficCol("↑ Отдача", formatBytes(vpnState.totalUpload))
                        }
                    }
                }
            }

            // Server info
            if (vpnState.currentServer != null) {
                item {
                    Card(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 4.dp), RoundedCornerShape(14.dp), colors = CardDefaults.cardColors(Color.White.copy(0.06f))) {
                        Row(Modifier.fillMaxWidth().padding(16.dp), horizontalArrangement = Arrangement.SpaceEvenly) {
                            TrafficCol("Пинг", if (vpnState.currentServer!!.ping >= 0) "${vpnState.currentServer!!.ping}ms" else "---")
                            TrafficCol("Сервер", vpnState.currentServer!!.name)
                        }
                    }
                }
            }

            // Happ-style buttons
            item {
                Row(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    HappButton("Обновить конфигурацию", Icons.Outlined.Refresh, Modifier.weight(1f)) { viewModel.refreshSubscriptions() }
                    HappButton("Проверка пинга", Icons.Outlined.Speed, Modifier.weight(1f)) { viewModel.testAllPings() }
                }
            }

            // Protocol filter
            item {
                Row(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 4.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Chip("Все", selectedProtocol == null) { viewModel.filterByProtocol(null) }
                    Protocol.entries.take(4).forEach { p -> Chip(p.displayName, selectedProtocol == p) { viewModel.filterByProtocol(p) } }
                }
            }

            // Servers
            val filtered = if (selectedProtocol != null) servers.filter { it.protocol == selectedProtocol } else servers
            if (filtered.isEmpty()) {
                item {
                    Column(Modifier.fillMaxWidth().padding(40.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(Icons.Outlined.CloudOff, null, Modifier.size(48.dp), tint = Color.White.copy(0.3f))
                        Spacer(Modifier.height(12.dp))
                        Text("Нет серверов", fontSize = 16.sp, color = Color.White.copy(0.5f))
                        Text("Нажмите + или вставьте из буфера", fontSize = 13.sp, color = Color.White.copy(0.3f))
                    }
                }
            } else {
                items(filtered) { s ->
                    ServerCard(s, s.id == vpnState.currentServer?.id, { viewModel.selectServer(s) }, { viewModel.testPing(s) })
                }
            }
        }
    }

    if (showAddDialog) AddSubDialog({ viewModel.showAddSubscription(false) }) { u, n -> viewModel.addSubscription(u, n) }
    if (showSettings) SettingsDlg({ showSettings = false })
    error?.let { Snackbar(Modifier.padding(16.dp), containerColor = Color(0xFF2D1B69), contentColor = Color.White, action = { TextButton({ viewModel.dismissError() }) { Text("OK", color = Color(0xFF7C6CFF)) } }) { Text(it) } }
}

private fun importFromClipboard(context: Context, viewModel: MainViewModel) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val clip = cm.primaryClip
    if (clip != null && clip.itemCount > 0) {
        val text = clip.getItemAt(0).text?.toString() ?: ""
        if (text.isNotBlank() && (text.contains("://") || text.startsWith("http"))) {
            viewModel.addSubscription(text, "Подписка из буфера")
        } else {
            viewModel.showError("В буфере нет ссылки подписки")
        }
    } else {
        viewModel.showError("Буфер обмена пуст")
    }
}

private fun formatBytes(bytes: Long): String = when {
    bytes < 1024 -> "${bytes}B"
    bytes < 1048576 -> "${bytes / 1024}KB"
    bytes < 1073741824 -> "${"%.1f".format(bytes / 1048576.0)}MB"
    else -> "${"%.2f".format(bytes / 1073741824.0)}GB"
}

@Composable
fun TrafficCol(label: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(label, fontSize = 12.sp, color = Color.White.copy(0.5f))
        Text(value, fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Color(0xFF7C6CFF))
    }
}

@Composable
fun HappButton(text: String, icon: androidx.compose.ui.graphics.vector.ImageVector, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Card(modifier.clickable { onClick() }, RoundedCornerShape(12.dp), colors = CardDefaults.cardColors(Color(0xFF7C6CFF).copy(0.15f))) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.Center) {
            Icon(icon, null, Modifier.size(18.dp), tint = Color(0xFF7C6CFF))
            Spacer(Modifier.width(8.dp))
            Text(text, fontSize = 13.sp, fontWeight = FontWeight.Medium, color = Color(0xFF7C6CFF))
        }
    }
}

@Composable
fun PowerButton(connected: Boolean, connecting: Boolean, onClick: () -> Unit) {
    val t = rememberInfiniteTransition("p")
    val pulse by t.animateFloat(0.15f, 0.4f, infiniteRepeatable(tween(1500, easing = FastOutSlowInEasing), RepeatMode.Reverse), "pa")
    val scale by t.animateFloat(1f, 1.2f, infiniteRepeatable(tween(1500, easing = FastOutSlowInEasing), RepeatMode.Reverse), "ps")
    val rot by t.animateFloat(0f, 360f, infiniteRepeatable(tween(6000, easing = LinearEasing), RepeatMode.Restart), "r")
    val col = when { connected -> Color(0xFF00E676); connecting -> Color(0xFFFFAB00); else -> Color(0xFF7C6CFF) }

    Box(Modifier.size(180.dp), contentAlignment = Alignment.Center) {
        if (connected || connecting) Canvas(Modifier.fillMaxSize()) { drawCircle(col.copy(alpha = pulse * 0.2f), radius = size.minDimension / 2 * scale) }
        Canvas(Modifier.fillMaxSize()) {
            val r = size.minDimension / 2 - 8.dp.toPx()
            for (i in 0..15) {
                val a = Math.toRadians((i * 22.5 + rot).toDouble())
                drawCircle(col.copy(alpha = 0.4f), 2.dp.toPx(), Offset(center.x + r * cos(a).toFloat(), center.y + r * sin(a).toFloat()))
            }
        }
        Box(Modifier.size(140.dp).shadow(24.dp, CircleShape, ambientColor = col.copy(0.5f), spotColor = col).clip(CircleShape)
            .background(Brush.radialGradient(listOf(col.copy(0.2f), col.copy(0.05f), Color.Transparent))).clickable { onClick() },
            contentAlignment = Alignment.Center) {
            Box(Modifier.size(110.dp).shadow(12.dp, CircleShape, ambientColor = col).clip(CircleShape)
                .background(Brush.verticalGradient(listOf(col, col.copy(0.7f)))),
                contentAlignment = Alignment.Center) {
                Icon(
                    when { connecting -> Icons.Filled.Sync; connected -> Icons.Filled.Link; else -> Icons.Filled.PowerSettingsNew },
                    if (connected) "Отключить" else "Подключить", tint = Color.White, modifier = Modifier.size(44.dp)
                )
            }
        }
    }
}

@Composable
fun ServerCard(server: VPNServer, selected: Boolean, onClick: () -> Unit, onPing: () -> Unit) {
    Card(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 3.dp).clickable { onClick() }, RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(if (selected) Color(0xFF7C6CFF).copy(0.15f) else Color.White.copy(0.05f))) {
        Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(server.flag, fontSize = 26.sp)
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(server.name, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = Color.White, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text("${server.protocol.displayName} • ${server.country}", fontSize = 11.sp, color = Color.White.copy(0.45f), maxLines = 1)
            }
            if (server.ping >= 0) {
                val c = when { server.ping < 100 -> Color(0xFF00E676); server.ping < 300 -> Color(0xFFFFAB00); else -> Color(0xFFFF6B6B) }
                Surface(shape = RoundedCornerShape(6.dp), color = c.copy(0.15f)) { Text("${server.ping}ms", Modifier.padding(horizontal = 6.dp, vertical = 3.dp), fontSize = 11.sp, color = c) }
            }
            if (selected) { Spacer(Modifier.width(6.dp)); Icon(Icons.Filled.Check, "Выбран", tint = Color(0xFF7C6CFF), modifier = Modifier.size(18.dp)) }
        }
    }
}

@Composable
fun Chip(label: String, sel: Boolean, onClick: () -> Unit) {
    Surface(Modifier.clickable { onClick() }, RoundedCornerShape(20.dp), color = if (sel) Color(0xFF7C6CFF) else Color.White.copy(0.08f)) {
        Text(label, Modifier.padding(horizontal = 12.dp, vertical = 5.dp), fontSize = 12.sp, color = if (sel) Color.White else Color.White.copy(0.5f))
    }
}

@Composable
fun AddSubDialog(onDismiss: () -> Unit, onAdd: (String, String) -> Unit) {
    var url by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    AlertDialog(onDismissRequest = onDismiss, containerColor = Color(0xFF1A1145), titleContentColor = Color.White, textContentColor = Color.White.copy(0.8f),
        title = { Text("Добавить подписку", fontWeight = FontWeight.Bold) },
        text = {
            Column {
                OutlinedTextField(name, { name = it }, label = { Text("Название") }, modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(focusedBorderColor = Color(0xFF7C6CFF), unfocusedBorderColor = Color.White.copy(0.2f), focusedTextColor = Color.White, unfocusedTextColor = Color.White, cursorColor = Color(0xFF7C6CFF)), singleLine = true)
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(url, { url = it }, label = { Text("Ссылка подписки") }, modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(focusedBorderColor = Color(0xFF7C6CFF), unfocusedBorderColor = Color.White.copy(0.2f), focusedTextColor = Color.White, unfocusedTextColor = Color.White, cursorColor = Color(0xFF7C6CFF)), singleLine = true)
                Spacer(Modifier.height(8.dp))
                Text("VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC", fontSize = 11.sp, color = Color.White.copy(0.4f))
            }
        },
        confirmButton = { Button({ onAdd(url.ifEmpty { "https://" }, name.ifEmpty { "Подписка" }) }, enabled = url.isNotEmpty(), colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF7C6CFF)), shape = RoundedCornerShape(10.dp)) { Text("Добавить") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена", color = Color.White.copy(0.6f)) } }
    )
}

@Composable
fun SettingsDlg(onDismiss: () -> Unit) {
    AlertDialog(onDismissRequest = onDismiss, containerColor = Color(0xFF1A1145), titleContentColor = Color.White, textContentColor = Color.White.copy(0.8f),
        title = { Text("Настройки", fontWeight = FontWeight.Bold) },
        text = { Text("QuantumVPN v1.2.0\n\nПротоколы: VLESS, VMess, Trojan, Shadowsocks\nHysteria2, TUIC, WireGuard", fontSize = 14.sp, lineHeight = 22.sp) },
        confirmButton = { Button(onDismiss, colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF7C6CFF)), shape = RoundedCornerShape(10.dp)) { Text("Закрыть") } }
    )
}
