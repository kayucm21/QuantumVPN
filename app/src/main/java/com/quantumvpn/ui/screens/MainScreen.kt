package com.quantumvpn.ui.screens

import android.Manifest
import android.app.Activity
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
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import com.google.zxing.integration.android.ScanContract
import com.google.zxing.integration.android.ScanOptions
import com.quantumvpn.data.*
import com.quantumvpn.viewmodel.MainViewModel
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(viewModel: MainViewModel = viewModel()) {
    val context = LocalContext.current
    val configuration = LocalConfiguration.current
    val density = LocalDensity.current
    val vpnState by viewModel.vpnState.collectAsState()
    val servers by viewModel.servers.collectAsState()
    val subscriptions by viewModel.subscriptions.collectAsState()
    val error by viewModel.error.collectAsState()
    val infoMessage by viewModel.infoMessage.collectAsState()
    val showAddDialog by viewModel.showAddSubscription.collectAsState()
    val isRefreshing by viewModel.isRefreshing.collectAsState()
    val isPinging by viewModel.isPinging.collectAsState()

    val snackbarHostState = remember { SnackbarHostState() }

    var showSettings by remember { mutableStateOf(false) }
    var vpnPermOk by remember { mutableStateOf(false) }
    var notifPermOk by remember { mutableStateOf(false) }
    var panelExpanded by remember { mutableStateOf(servers.isNotEmpty()) }

    val vpnLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        vpnPermOk = r.resultCode == Activity.RESULT_OK
        if (vpnPermOk) viewModel.connectVPN()
    }
    val notifLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { notifPermOk = it }

    val qrLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        if (result.contents != null) {
            viewModel.importFromText(result.contents, "QR импорт")
        }
    }

    val cameraLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) launchQrScanner(qrLauncher)
        else viewModel.showError("Нужен доступ к камере для QR")
    }

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
    LaunchedEffect(error) {
        error?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.dismissError()
        }
    }
    LaunchedEffect(infoMessage) {
        infoMessage?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.dismissInfo()
        }
    }
    LaunchedEffect(servers.isNotEmpty()) {
        if (servers.isNotEmpty()) panelExpanded = true
    }

    val maxContentWidth = min(configuration.screenWidthDp, 400).dp
    val normalizedDensity = Density(density.density, density.fontScale.coerceAtMost(1.1f))

    CompositionLocalProvider(LocalDensity provides normalizedDensity) {
        Scaffold(
            snackbarHost = { SnackbarHost(snackbarHostState) },
            containerColor = Color(0xFFF5F5F7)
        ) { padding ->
            Box(
                Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .background(Color(0xFFF5F5F7)),
                contentAlignment = Alignment.TopCenter
            ) {
                Column(
                    Modifier
                        .widthIn(max = maxContentWidth)
                        .fillMaxHeight()
                ) {
                    Row(
                        Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        IconButton(onClick = { showSettings = true }) {
                            Icon(Icons.Outlined.Settings, "Настройки", tint = Color(0xFF6366F1), modifier = Modifier.size(22.dp))
                        }
                        Row {
                            IconButton(onClick = { viewModel.importFromClipboard() }) {
                                Icon(Icons.Outlined.ContentPaste, "Буфер", tint = Color(0xFF6366F1), modifier = Modifier.size(22.dp))
                            }
                            IconButton(onClick = {
                                if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                                    launchQrScanner(qrLauncher)
                                } else {
                                    cameraLauncher.launch(Manifest.permission.CAMERA)
                                }
                            }) {
                                Icon(Icons.Outlined.QrCode, "QR", tint = Color(0xFF6366F1), modifier = Modifier.size(22.dp))
                            }
                            IconButton(onClick = { viewModel.showAddSubscription(true) }) {
                                Icon(Icons.Filled.Add, "Добавить", tint = Color(0xFF1A1C1E), modifier = Modifier.size(24.dp))
                            }
                        }
                    }

                    Column(
                        Modifier.weight(1f).fillMaxWidth(),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        HappPowerButton(
                            connected = vpnState.isConnected,
                            connecting = vpnState.isConnecting,
                            maxSize = min(configuration.screenWidthDp * 0.42f, 160f).dp
                        ) {
                            if (!vpnPermOk) VpnService.prepare(context)?.let { vpnLauncher.launch(it) }
                            else viewModel.toggleConnection()
                        }

                        Spacer(Modifier.height(24.dp))

                        Text(
                            when {
                                vpnState.isConnecting -> "Подключение..."
                                vpnState.isConnected -> "Подключено"
                                else -> "Отключено"
                            },
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Medium,
                            color = Color(0xFF1A1C1E)
                        )

                        if (vpnState.currentServer != null) {
                            Spacer(Modifier.height(4.dp))
                            Text(
                                "${vpnState.currentServer!!.flag} ${vpnState.currentServer!!.name} • ${vpnState.currentServer!!.protocol.displayName}",
                                fontSize = 12.sp,
                                color = Color(0xFF888888),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.padding(horizontal = 16.dp)
                            )
                        }
                    }

                    Surface(
                        Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(topStart = 16.dp, topEnd = 16.dp),
                        color = Color.White,
                        shadowElevation = 6.dp
                    ) {
                        Column(Modifier.fillMaxWidth().padding(bottom = 12.dp)) {
                            Row(
                                Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    if (panelExpanded) Icons.Filled.ExpandMore else Icons.Filled.ExpandLess,
                                    null,
                                    tint = Color(0xFF888888),
                                    modifier = Modifier.size(20.dp).clickable { panelExpanded = !panelExpanded }
                                )
                                Spacer(Modifier.width(6.dp))
                                Column(Modifier.weight(1f)) {
                                    val subName = subscriptions.firstOrNull()?.name ?: "Серверы"
                                    Text(subName, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFF1A1C1E))
                                    Text("Серверов: ${servers.size}", fontSize = 11.sp, color = Color(0xFF888888))
                                }
                                IconButton(
                                    onClick = { viewModel.refreshSubscriptions() },
                                    enabled = !isRefreshing,
                                    modifier = Modifier.size(36.dp)
                                ) {
                                    if (isRefreshing) {
                                        CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = Color(0xFF6366F1))
                                    } else {
                                        Icon(Icons.Outlined.Refresh, "Обновить", tint = Color(0xFF6366F1), modifier = Modifier.size(18.dp))
                                    }
                                }
                                IconButton(
                                    onClick = { viewModel.testAllPings() },
                                    enabled = !isPinging,
                                    modifier = Modifier.size(36.dp)
                                ) {
                                    if (isPinging) {
                                        CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = Color(0xFF6366F1))
                                    } else {
                                        Icon(Icons.Outlined.Speed, "Пинг", tint = Color(0xFF6366F1), modifier = Modifier.size(18.dp))
                                    }
                                }
                            }

                            if (vpnState.isConnected) {
                                Surface(
                                    Modifier.fillMaxWidth().padding(horizontal = 12.dp).clip(RoundedCornerShape(8.dp)),
                                    color = Color(0xFFF0F0FF)
                                ) {
                                    Row(Modifier.padding(horizontal = 12.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                                        Icon(Icons.Outlined.Info, null, tint = Color(0xFF6366F1), modifier = Modifier.size(14.dp))
                                        Spacer(Modifier.width(6.dp))
                                        Text(
                                            "↓ ${formatBytes(vpnState.totalDownload)}  ↑ ${formatBytes(vpnState.totalUpload)}",
                                            fontSize = 11.sp,
                                            fontWeight = FontWeight.Medium,
                                            color = Color(0xFF6366F1)
                                        )
                                    }
                                }
                                Spacer(Modifier.height(6.dp))
                            }

                            if (panelExpanded) {
                                if (servers.isEmpty()) {
                                    Column(
                                        Modifier.fillMaxWidth().padding(24.dp),
                                        horizontalAlignment = Alignment.CenterHorizontally
                                    ) {
                                        Icon(Icons.Outlined.CloudOff, null, Modifier.size(36.dp), tint = Color(0xFFCCCCCC))
                                        Spacer(Modifier.height(10.dp))
                                        Text("Добавьте подписку или конфиг", fontSize = 13.sp, color = Color(0xFF888888), textAlign = TextAlign.Center)
                                        Spacer(Modifier.height(16.dp))
                                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                                            ImportButton("Буфер", Icons.Outlined.ContentPaste) { viewModel.importFromClipboard() }
                                            ImportButton("QR", Icons.Outlined.QrCode) {
                                                if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                                                    launchQrScanner(qrLauncher)
                                                } else {
                                                    cameraLauncher.launch(Manifest.permission.CAMERA)
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    LazyColumn(
                                        Modifier.fillMaxWidth().heightIn(max = 280.dp),
                                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 2.dp)
                                    ) {
                                        items(servers, key = { it.id }) { server ->
                                            HappServerCard(
                                                server = server,
                                                selected = server.id == vpnState.currentServer?.id,
                                                onClick = { viewModel.selectServer(server) },
                                                onPing = { viewModel.testPing(server) }
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
    }

    if (showAddDialog) {
        AddSubDialog(
            onDismiss = { viewModel.showAddSubscription(false) },
            onAdd = { u, n -> viewModel.addSubscription(u, n) },
            onPaste = { viewModel.importFromClipboard() },
            onQr = {
                if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                    launchQrScanner(qrLauncher)
                } else {
                    cameraLauncher.launch(Manifest.permission.CAMERA)
                }
            }
        )
    }
    if (showSettings) SettingsDlg({ showSettings = false })
}

private fun launchQrScanner(launcher: androidx.activity.result.ActivityResultLauncher<ScanOptions>) {
    val options = ScanOptions().apply {
        setDesiredBarcodeFormats(ScanOptions.QR_CODE)
        setPrompt("Наведите камеру на QR-код")
        setBeepEnabled(false)
        setOrientationLocked(true)
        setBarcodeImageEnabled(false)
    }
    launcher.launch(options)
}

@Composable
fun HappPowerButton(connected: Boolean, connecting: Boolean, maxSize: androidx.compose.ui.unit.Dp, onClick: () -> Unit) {
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

    val innerSize = maxSize * 0.68f
    val iconSize = maxSize * 0.26f

    Box(Modifier.size(maxSize), contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            drawCircle(color = ringColor.copy(alpha = 0.08f), radius = size.minDimension / 2)
        }
        Canvas(Modifier.fillMaxSize().graphicsLayer { scaleX = outerScale; scaleY = outerScale }) {
            drawCircle(
                color = ringColor.copy(alpha = outerAlpha * 0.15f),
                radius = size.minDimension / 2 - 4.dp.toPx(),
                style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round)
            )
        }
        Canvas(Modifier.fillMaxSize()) {
            val cx = center.x
            val cy = center.y
            val r = size.minDimension / 2 - 12.dp.toPx()
            drawArc(
                color = arcColor.copy(alpha = 0.25f), startAngle = rot, sweepAngle = 60f,
                useCenter = false, style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round),
                topLeft = Offset(cx - r, cy - r), size = androidx.compose.ui.geometry.Size(r * 2, r * 2)
            )
            for (i in 0..7) {
                val a = Math.toRadians((i * 45.0 + rot))
                drawCircle(
                    color = ringColor.copy(alpha = 0.3f), radius = 1.2.dp.toPx(),
                    center = Offset(cx + r * cos(a).toFloat(), cy + r * sin(a).toFloat())
                )
            }
        }
        Box(
            Modifier
                .size(innerSize)
                .shadow(12.dp, CircleShape)
                .clip(CircleShape)
                .background(Color.White)
                .clickable { onClick() },
            contentAlignment = Alignment.Center
        ) {
            Icon(
                if (connecting) Icons.Filled.Sync else Icons.Filled.PowerSettingsNew,
                contentDescription = if (connected) "Отключить" else "Подключить",
                tint = when {
                    connected -> Color(0xFF22C55E)
                    connecting -> Color(0xFFF59E0B)
                    else -> Color(0xFFCCCCCC)
                },
                modifier = Modifier.size(iconSize)
            )
        }
    }
}

@Composable
fun HappServerCard(server: VPNServer, selected: Boolean, onClick: () -> Unit, onPing: () -> Unit) {
    Surface(
        Modifier.fillMaxWidth().padding(vertical = 2.dp).clickable { onClick() },
        shape = RoundedCornerShape(10.dp),
        color = if (selected) Color(0xFFF0F0FF) else Color.Transparent
    ) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Outlined.Language, null, tint = Color(0xFF6366F1), modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(server.name, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFF1A1C1E), maxLines = 1, overflow = TextOverflow.Ellipsis)
                val proto = server.protocol.displayName
                val transport = server.settings["transport"]?.toString()?.uppercase() ?: ""
                Text(proto + if (transport.isNotEmpty()) " / $transport" else "", fontSize = 11.sp, color = Color(0xFF888888), maxLines = 1)
            }
            Text(
                text = when {
                    server.ping == -2L -> "..."
                    server.ping >= 0 -> "${server.ping}ms"
                    server.ping == -1L -> "—"
                    else -> ""
                },
                fontSize = 11.sp,
                fontWeight = FontWeight.Medium,
                color = when {
                    server.ping >= 0 && server.ping < 200 -> Color(0xFF22C55E)
                    server.ping >= 200 -> Color(0xFFF59E0B)
                    server.ping == -1L -> Color(0xFFEF4444)
                    else -> Color(0xFF888888)
                },
                modifier = Modifier.clickable { onPing() }.padding(horizontal = 4.dp)
            )
            Icon(Icons.Filled.ChevronRight, null, tint = Color(0xFFCCCCCC), modifier = Modifier.size(18.dp))
        }
    }
}

@Composable
fun ImportButton(text: String, icon: androidx.compose.ui.graphics.vector.ImageVector, onClick: () -> Unit) {
    Surface(
        Modifier.clickable { onClick() },
        shape = RoundedCornerShape(10.dp),
        color = Color(0xFFF0F0FF)
    ) {
        Row(Modifier.padding(horizontal = 14.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, tint = Color(0xFF6366F1), modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(6.dp))
            Text(text, fontSize = 12.sp, fontWeight = FontWeight.Medium, color = Color(0xFF6366F1))
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
fun AddSubDialog(
    onDismiss: () -> Unit,
    onAdd: (String, String) -> Unit,
    onPaste: () -> Unit,
    onQr: () -> Unit
) {
    var url by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Color.White,
        title = { Text("Добавить подписку", fontWeight = FontWeight.Bold, fontSize = 16.sp) },
        text = {
            Column {
                OutlinedTextField(
                    name, { name = it }, label = { Text("Название") },
                    modifier = Modifier.fillMaxWidth(), singleLine = true,
                    colors = fieldColors()
                )
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(
                    url, { url = it },
                    label = { Text("Ссылка или конфиг") },
                    placeholder = { Text("https://... или vless://...") },
                    modifier = Modifier.fillMaxWidth(), singleLine = false, maxLines = 3,
                    colors = fieldColors()
                )
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = onPaste) {
                        Icon(Icons.Outlined.ContentPaste, null, Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Буфер", fontSize = 12.sp)
                    }
                    TextButton(onClick = onQr) {
                        Icon(Icons.Outlined.QrCode, null, Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("QR", fontSize = 12.sp)
                    }
                }
            }
        },
        confirmButton = {
            Button(
                { onAdd(url.trim(), name.ifEmpty { "Подписка" }) },
                enabled = url.isNotBlank(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6366F1))
            ) { Text("Добавить") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена", color = Color(0xFF888888)) } }
    )
}

@Composable
private fun fieldColors() = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = Color(0xFF6366F1),
    unfocusedBorderColor = Color(0xFFDDDDDD),
    focusedTextColor = Color(0xFF1A1C1E),
    unfocusedTextColor = Color(0xFF1A1C1E),
    cursorColor = Color(0xFF6366F1)
)

@Composable
fun SettingsDlg(onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Color.White,
        title = { Text("Настройки", fontWeight = FontWeight.Bold) },
        text = {
            Text(
                "QuantumVPN v1.8.0\n\nПротоколы: VLESS, VMess, Trojan, Shadowsocks\nHysteria2, TUIC",
                fontSize = 13.sp, lineHeight = 20.sp
            )
        },
        confirmButton = {
            Button(onDismiss, colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6366F1))) {
                Text("Закрыть")
            }
        }
    )
}
