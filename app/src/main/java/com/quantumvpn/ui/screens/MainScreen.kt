package com.quantumvpn.ui.screens

import android.Manifest
import android.app.Activity
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
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
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(viewModel: MainViewModel = viewModel()) {
    val context = LocalContext.current
    val vpnState by viewModel.vpnState.collectAsState()
    val servers by viewModel.servers.collectAsState()
    val subscriptions by viewModel.subscriptions.collectAsState()
    val error by viewModel.error.collectAsState()
    val showAddDialog by viewModel.showAddSubscription.collectAsState()

    var showSettings by remember { mutableStateOf(false) }
    var vpnPermOk by remember { mutableStateOf(false) }
    var notifPermOk by remember { mutableStateOf(false) }
    var panelExpanded by remember { mutableStateOf(servers.isNotEmpty()) }

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

    Box(Modifier.fillMaxSize().background(Color(0xFFF5F5F7))) {
        Column(Modifier.fillMaxSize()) {
            // Top bar
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = { showSettings = true }) {
                    Icon(Icons.Outlined.Settings, "Настройки", tint = Color(0xFF6366F1), modifier = Modifier.size(26.dp))
                }
                IconButton(onClick = { viewModel.showAddSubscription(true) }) {
                    Icon(Icons.Filled.Add, "Добавить", tint = Color(0xFF1A1C1E), modifier = Modifier.size(28.dp))
                }
            }

            // Center content
            Column(
                Modifier.weight(1f).fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                // Power button
                HappPowerButton(
                    connected = vpnState.isConnected,
                    connecting = vpnState.isConnecting
                ) {
                    if (!vpnPermOk) VpnService.prepare(context)?.let { vpnLauncher.launch(it) }
                    else viewModel.toggleConnection()
                }

                Spacer(Modifier.height(40.dp))

                // Status text
                Text(
                    when {
                        vpnState.isConnecting -> "Подключение..."
                        vpnState.isConnected -> "Подключено"
                        else -> "Отключено"
                    },
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Medium,
                    color = Color(0xFF1A1C1E)
                )

                // Selected server info
                if (vpnState.currentServer != null) {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "${vpnState.currentServer!!.flag} ${vpnState.currentServer!!.name} • ${vpnState.currentServer!!.protocol.displayName}",
                        fontSize = 13.sp,
                        color = Color(0xFF888888)
                    )
                }
            }

            // Bottom panel
            Surface(
                Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(topStart = 20.dp, topEnd = 20.dp),
                color = Color.White,
                shadowElevation = 8.dp
            ) {
                Column(Modifier.fillMaxWidth().padding(bottom = 16.dp)) {
                    // Subscription header
                    Row(
                        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        // Chevron
                        Icon(
                            if (panelExpanded) Icons.Filled.ExpandMore else Icons.Filled.ExpandLess,
                            null,
                            tint = Color(0xFF888888),
                            modifier = Modifier.size(22.dp).clickable { panelExpanded = !panelExpanded }
                        )
                        Spacer(Modifier.width(8.dp))
                        Column(Modifier.weight(1f)) {
                            val subName = subscriptions.firstOrNull()?.name ?: "VPN"
                            Text(subName, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFF1A1C1E))
                            Text("Серверов: ${servers.size}", fontSize = 11.sp, color = Color(0xFF888888))
                        }
                        // Action buttons
                        IconButton(onClick = { viewModel.refreshSubscriptions() }, modifier = Modifier.size(32.dp)) {
                            Icon(Icons.Outlined.Refresh, "Обновить", tint = Color(0xFF6366F1), modifier = Modifier.size(18.dp))
                        }
                        IconButton(onClick = { viewModel.testAllPings() }, modifier = Modifier.size(32.dp)) {
                            Icon(Icons.Outlined.Speed, "Пинг", tint = Color(0xFF6366F1), modifier = Modifier.size(18.dp))
                        }
                        IconButton(onClick = { showSettings = true }, modifier = Modifier.size(32.dp)) {
                            Icon(Icons.Outlined.MoreVert, "Ещё", tint = Color(0xFF888888), modifier = Modifier.size(18.dp))
                        }
                    }

                    // Traffic bar
                    if (vpnState.isConnected) {
                        Surface(
                            Modifier.fillMaxWidth().padding(horizontal = 16.dp).clip(RoundedCornerShape(10.dp)),
                            color = Color(0xFFF0F0FF)
                        ) {
                            Row(Modifier.padding(horizontal = 14.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Outlined.Info, null, tint = Color(0xFF6366F1), modifier = Modifier.size(16.dp))
                                Spacer(Modifier.width(8.dp))
                                Text(
                                    "↓ ${formatBytes(vpnState.totalDownload)}  ↑ ${formatBytes(vpnState.totalUpload)}",
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = Color(0xFF6366F1),
                                    modifier = Modifier.weight(1f)
                                )
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                    }

                    if (panelExpanded) {
                        // "Скрыть все" link
                        Text(
                            "Скрыть все",
                            Modifier.fillMaxWidth().padding(horizontal = 16.dp).clickable { panelExpanded = false },
                            textAlign = TextAlign.End,
                            fontSize = 13.sp,
                            color = Color(0xFF888888)
                        )
                        Spacer(Modifier.height(4.dp))

                        if (servers.isEmpty()) {
                            // Empty state
                            Column(
                                Modifier.fillMaxWidth().padding(32.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Spacer(Modifier.height(20.dp))
                                Icon(Icons.Outlined.CloudOff, null, Modifier.size(40.dp), tint = Color(0xFFCCCCCC))
                                Spacer(Modifier.height(12.dp))
                                Text("Чтобы использовать приложение, вам необходимо", fontSize = 13.sp, color = Color(0xFF888888), textAlign = TextAlign.Center)
                                Text("добавить прокси-сервер и/или подписку в список серверов.", fontSize = 13.sp, color = Color(0xFF888888), textAlign = TextAlign.Center)
                                Spacer(Modifier.height(20.dp))
                                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                    ImportButton("Из буфера", Icons.Outlined.ContentPaste) {
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
                                    ImportButton("QR-Код", Icons.Outlined.QrCode) {
                                        viewModel.showAddSubscription(true)
                                    }
                                }
                            }
                        } else {
                            // Server list
                            LazyColumn(
                                Modifier.fillMaxWidth(),
                                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 4.dp)
                            ) {
                                items(servers) { server ->
                                    HappServerCard(
                                        server = server,
                                        selected = server.id == vpnState.currentServer?.id,
                                        onClick = { viewModel.selectServer(server) }
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (showAddDialog) AddSubDialog({ viewModel.showAddSubscription(false) }) { u, n -> viewModel.addSubscription(u, n) }
    if (showSettings) SettingsDlg({ showSettings = false })
    error?.let {
        Snackbar(
            Modifier.padding(16.dp),
            containerColor = Color(0xFF1A1C1E),
            contentColor = Color.White,
            action = { TextButton({ viewModel.dismissError() }) { Text("OK", color = Color(0xFF818CF8)) } }
        ) { Text(it) }
    }
}

@Composable
fun HappPowerButton(connected: Boolean, connecting: Boolean, onClick: () -> Unit) {
    val t = rememberInfiniteTransition("pulse")

    val outerAlpha by t.animateFloat(0.15f, 0.35f, infiniteRepeatable(tween(2000, easing = FastOutSlowInEasing), RepeatMode.Reverse), "oa")
    val outerScale by t.animateFloat(0.95f, 1.05f, infiniteRepeatable(tween(2000, easing = FastOutSlowInEasing), RepeatMode.Reverse), "os")
    val rot by t.animateFloat(0f, 360f, infiniteRepeatable(tween(10000, easing = LinearEasing), RepeatMode.Restart), "rot")

    val ringColor = when {
        connected -> Color(0xFF22C55E)
        connecting -> Color(0xFFF59E0B)
        else -> Color(0xFFE8E8EC)
    }
    val arcColor = when {
        connected -> Color(0xFF22C55E)
        connecting -> Color(0xFFF59E0B)
        else -> Color(0xFF6366F1)
    }

    Box(Modifier.size(220.dp), contentAlignment = Alignment.Center) {
        // Outer subtle circle
        Canvas(Modifier.fillMaxSize()) {
            drawCircle(
                color = ringColor.copy(alpha = 0.08f),
                radius = size.minDimension / 2
            )
        }

        // Animated outer ring
        Canvas(Modifier.fillMaxSize().graphicsLayer { scaleX = outerScale; scaleY = outerScale }) {
            drawCircle(
                color = ringColor.copy(alpha = outerAlpha * 0.15f),
                radius = size.minDimension / 2 - 4.dp.toPx(),
                style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round)
            )
        }

        // Rotating arcs
        Canvas(Modifier.fillMaxSize()) {
            val cx = center.x
            val cy = center.y
            val r = size.minDimension / 2 - 16.dp.toPx()

            val arc1Start = Math.toRadians(rot.toDouble())
            val arc1End = arc1Start + Math.toRadians(60.0)
            drawArc(
                color = arcColor.copy(alpha = 0.25f),
                startAngle = rot,
                sweepAngle = 60f,
                useCenter = false,
                style = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round),
                topLeft = Offset(cx - r, cy - r),
                size = androidx.compose.ui.geometry.Size(r * 2, r * 2)
            )
            drawArc(
                color = arcColor.copy(alpha = 0.12f),
                startAngle = rot + 180f,
                sweepAngle = 60f,
                useCenter = false,
                style = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round),
                topLeft = Offset(cx - r, cy - r),
                size = androidx.compose.ui.geometry.Size(r * 2, r * 2)
            )

            // Rotating dots
            for (i in 0..7) {
                val a = Math.toRadians((i * 45.0 + rot))
                val px = cx + r * cos(a).toFloat()
                val py = cy + r * sin(a).toFloat()
                drawCircle(
                    color = ringColor.copy(alpha = 0.3f),
                    radius = 1.5.dp.toPx(),
                    center = Offset(px, py)
                )
            }
        }

        // Main button - white with shadow
        Box(
            Modifier
                .size(150.dp)
                .shadow(16.dp, CircleShape, ambientColor = Color(0x20000000), spotColor = Color(0x20000000))
                .clip(CircleShape)
                .background(Color.White)
                .clickable { onClick() },
            contentAlignment = Alignment.Center
        ) {
            // Inner ring
            Canvas(Modifier.size(120.dp)) {
                drawCircle(
                    color = ringColor.copy(alpha = 0.1f),
                    radius = size.minDimension / 2,
                    style = Stroke(width = 1.5.dp.toPx())
                )
            }

            // Icon
            Icon(
                when {
                    connecting -> Icons.Filled.Sync
                    connected -> Icons.Filled.PowerSettingsNew
                    else -> Icons.Filled.PowerSettingsNew
                },
                contentDescription = if (connected) "Отключить" else "Подключить",
                tint = when {
                    connected -> Color(0xFF22C55E)
                    connecting -> Color(0xFFF59E0B)
                    else -> Color(0xFFCCCCCC)
                },
                modifier = Modifier.size(48.dp)
            )
        }
    }
}

@Composable
fun HappServerCard(server: VPNServer, selected: Boolean, onClick: () -> Unit) {
    Surface(
        Modifier.fillMaxWidth().padding(vertical = 2.dp).clickable { onClick() },
        shape = RoundedCornerShape(12.dp),
        color = if (selected) Color(0xFFF0F0FF) else Color.Transparent
    ) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Globe icon
            Box(
                Modifier.size(36.dp).clip(RoundedCornerShape(8.dp)),
                contentAlignment = Alignment.Center
            ) {
                Icon(Icons.Outlined.Language, null, tint = Color(0xFF6366F1), modifier = Modifier.size(20.dp))
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(server.name, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFF1A1C1E), maxLines = 1, overflow = TextOverflow.Ellipsis)
                val proto = server.protocol.displayName
                val transport = server.settings["transport"]?.toString()?.uppercase() ?: ""
                val sec = server.settings["security"]?.toString()?.uppercase() ?: ""
                val parts = mutableListOf(proto)
                if (transport.isNotEmpty() && transport != "NONE") parts.add(transport)
                if (sec.isNotEmpty() && sec != "NONE" && sec != "FALSE") parts.add(sec)
                Text(parts.joinToString(" / "), fontSize = 12.sp, color = Color(0xFF888888), maxLines = 1)
            }
            // Arrow
            Icon(Icons.Filled.ChevronRight, null, tint = Color(0xFFCCCCCC), modifier = Modifier.size(20.dp))
        }
    }
}

@Composable
fun ImportButton(text: String, icon: androidx.compose.ui.graphics.vector.ImageVector, onClick: () -> Unit) {
    Surface(
        Modifier.clickable { onClick() },
        shape = RoundedCornerShape(12.dp),
        color = Color(0xFFF0F0FF),
        border = ButtonDefaults.outlinedButtonBorder.copy(brush = androidx.compose.ui.graphics.SolidColor(Color(0xFFE0E0FF)))
    ) {
        Row(Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, tint = Color(0xFF6366F1), modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(text, fontSize = 13.sp, fontWeight = FontWeight.Medium, color = Color(0xFF6366F1))
        }
    }
}

private fun formatBytes(bytes: Long): String = when {
    bytes < 1024 -> "${bytes}B"
    bytes < 1048576 -> "${bytes / 1024}KB"
    bytes < 1073741824 -> "${"%.1f".format(bytes / 1048576.0)}MB"
    else -> "${"%.2f".format(bytes / 1073741824.0)}GB"
}

@Composable
fun AddSubDialog(onDismiss: () -> Unit, onAdd: (String, String) -> Unit) {
    var url by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Color.White,
        titleContentColor = Color(0xFF1A1C1E),
        textContentColor = Color(0xFF44474E),
        title = { Text("Добавить подписку", fontWeight = FontWeight.Bold) },
        text = {
            Column {
                OutlinedTextField(
                    name, { name = it }, label = { Text("Название") },
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = Color(0xFF6366F1), unfocusedBorderColor = Color(0xFFDDDDDD),
                        focusedTextColor = Color(0xFF1A1C1E), unfocusedTextColor = Color(0xFF1A1C1E),
                        cursorColor = Color(0xFF6366F1)
                    ),
                    singleLine = true
                )
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    url, { url = it }, label = { Text("Ссылка подписки") },
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = Color(0xFF6366F1), unfocusedBorderColor = Color(0xFFDDDDDD),
                        focusedTextColor = Color(0xFF1A1C1E), unfocusedTextColor = Color(0xFF1A1C1E),
                        cursorColor = Color(0xFF6366F1)
                    ),
                    singleLine = true
                )
                Spacer(Modifier.height(8.dp))
                Text("VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC", fontSize = 11.sp, color = Color(0xFF888888))
            }
        },
        confirmButton = {
            Button(
                { onAdd(url.ifEmpty { "https://" }, name.ifEmpty { "Подписка" }) },
                enabled = url.isNotEmpty(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6366F1)),
                shape = RoundedCornerShape(10.dp)
            ) { Text("Добавить") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена", color = Color(0xFF888888)) } }
    )
}

@Composable
fun SettingsDlg(onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Color.White,
        titleContentColor = Color(0xFF1A1C1E),
        textContentColor = Color(0xFF44474E),
        title = { Text("Настройки", fontWeight = FontWeight.Bold) },
        text = {
            Text(
                "QuantumVPN v1.5.0\n\nПротоколы: VLESS, VMess, Trojan, Shadowsocks\nHysteria2, TUIC, WireGuard",
                fontSize = 14.sp, lineHeight = 22.sp
            )
        },
        confirmButton = {
            Button(
                onDismiss,
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6366F1)),
                shape = RoundedCornerShape(10.dp)
            ) { Text("Закрыть") }
        }
    )
}
