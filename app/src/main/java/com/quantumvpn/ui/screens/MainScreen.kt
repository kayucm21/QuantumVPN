package com.quantumvpn.ui.screens

import android.Manifest
import android.app.Activity
import android.content.Intent
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
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
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

@Composable
fun MainScreen(
    viewModel: MainViewModel = viewModel()
) {
    val context = LocalContext.current
    val vpnState by viewModel.vpnState.collectAsState()
    val servers by viewModel.servers.collectAsState()
    val connectionState by viewModel.connectionState.collectAsState()
    val showAddSubscription by viewModel.showAddSubscription.collectAsState()
    val error by viewModel.error.collectAsState()
    val selectedProtocol by viewModel.selectedProtocol.collectAsState()

    var showServerList by remember { mutableStateOf(false) }
    var showSettings by remember { mutableStateOf(false) }
    var vpnPermissionGranted by remember { mutableStateOf(false) }
    var notificationPermissionGranted by remember { mutableStateOf(false) }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        vpnPermissionGranted = result.resultCode == Activity.RESULT_OK
        if (vpnPermissionGranted) {
            viewModel.connectVPN()
        }
    }

    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        notificationPermissionGranted = granted
    }

    LaunchedEffect(Unit) {
        vpnPermissionGranted = VpnService.prepare(context) == null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notificationPermissionGranted = ContextCompat.checkSelfPermission(
                context, Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            notificationPermissionGranted = true
        }
    }

    LaunchedEffect(vpnState.isConnected, vpnState.isConnecting) {
        if (vpnState.isConnecting && !vpnPermissionGranted) {
            val intent = VpnService.prepare(context)
            if (intent != null) {
                vpnPermissionLauncher.launch(intent)
            }
        }
    }

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !notificationPermissionGranted) {
        LaunchedEffect(Unit) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF0D0B2E),
                        Color(0xFF1A1145),
                        Color(0xFF0D0B2E)
                    )
                )
            )
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(bottom = 100.dp)
        ) {
            // Top bar
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 20.dp, vertical = 16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconButton(onClick = { showSettings = true }) {
                        Icon(
                            Icons.Outlined.Settings,
                            contentDescription = "Настройки",
                            tint = Color.White.copy(alpha = 0.7f)
                        )
                    }
                    IconButton(onClick = { viewModel.showAddSubscription(true) }) {
                        Icon(
                            Icons.Filled.Add,
                            contentDescription = "Добавить подписку",
                            tint = Color.White
                        )
                    }
                }
            }

            // Brand name
            item {
                Text(
                    text = "кому ключи?",
                    modifier = Modifier.fillMaxWidth(),
                    textAlign = TextAlign.Center,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "нажми, чтобы подключить",
                    modifier = Modifier.fillMaxWidth(),
                    textAlign = TextAlign.Center,
                    fontSize = 13.sp,
                    color = Color.White.copy(alpha = 0.5f)
                )
            }

            // Power button
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 24.dp),
                    contentAlignment = Alignment.Center
                ) {
                    PowerButton(
                        isConnected = vpnState.isConnected,
                        isConnecting = vpnState.isConnecting,
                        onClick = {
                            if (!vpnPermissionGranted) {
                                val intent = VpnService.prepare(context)
                                if (intent != null) {
                                    vpnPermissionLauncher.launch(intent)
                                }
                            } else {
                                viewModel.toggleConnection()
                            }
                        }
                    )
                }
            }

            // Connection info
            if (vpnState.currentServer != null) {
                item {
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 20.dp),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(
                            containerColor = Color.White.copy(alpha = 0.08f)
                        )
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            horizontalArrangement = Arrangement.SpaceEvenly
                        ) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Text(
                                    text = "Пинг",
                                    fontSize = 12.sp,
                                    color = Color.White.copy(alpha = 0.5f)
                                )
                                Text(
                                    text = if (vpnState.currentServer!!.ping >= 0)
                                        "${vpnState.currentServer!!.ping}ms" else "---",
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF7C6CFF)
                                )
                            }
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Text(
                                    text = "Сервер",
                                    fontSize = 12.sp,
                                    color = Color.White.copy(alpha = 0.5f)
                                )
                                Text(
                                    text = vpnState.currentServer!!.name,
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    color = Color.White,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    modifier = Modifier.widthIn(max = 120.dp)
                                )
                            }
                        }
                    }
                }
            }

            // Server list header
            item {
                Spacer(modifier = Modifier.height(20.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 20.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Серверы",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = Color.White
                    )
                    Row {
                        TextButton(onClick = { viewModel.testAllPings() }) {
                            Text(
                                text = "Все пинги",
                                fontSize = 13.sp,
                                color = Color(0xFF7C6CFF)
                            )
                        }
                    }
                }
            }

            // Protocol filter chips
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 20.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    ProtocolChip("Все", selectedProtocol == null) { viewModel.filterByProtocol(null) }
                    Protocol.entries.take(4).forEach { protocol ->
                        ProtocolChip(
                            protocol.displayName,
                            selectedProtocol == protocol
                        ) { viewModel.filterByProtocol(protocol) }
                    }
                }
            }

            // Server cards
            val filteredServers = if (selectedProtocol != null) {
                servers.filter { it.protocol == selectedProtocol }
            } else {
                servers
            }

            if (filteredServers.isEmpty()) {
                item {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(40.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(
                            Icons.Outlined.CloudOff,
                            contentDescription = null,
                            modifier = Modifier.size(48.dp),
                            tint = Color.White.copy(alpha = 0.3f)
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "Нет серверов",
                            fontSize = 16.sp,
                            color = Color.White.copy(alpha = 0.5f)
                        )
                        Text(
                            text = "Добавьте подписку, чтобы начать",
                            fontSize = 13.sp,
                            color = Color.White.copy(alpha = 0.3f)
                        )
                        Spacer(modifier = Modifier.height(20.dp))
                        Button(
                            onClick = { viewModel.showAddSubscription(true) },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color(0xFF7C6CFF)
                            ),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Добавить подписку")
                        }
                    }
                }
            } else {
                items(filteredServers) { server ->
                    ServerCard(
                        server = server,
                        isSelected = server.id == vpnState.currentServer?.id,
                        onClick = { viewModel.selectServer(server) },
                        onPingClick = { viewModel.testPing(server) }
                    )
                }
            }
        }
    }

    if (showAddSubscription) {
        AddSubscriptionDialog(
            onDismiss = { viewModel.showAddSubscription(false) },
            onAdd = { url, name -> viewModel.addSubscription(url, name) }
        )
    }

    if (showServerList) {
        showServerList = false
    }

    if (showSettings) {
        SettingsDialog(
            onDismiss = { showSettings = false }
        )
    }

    error?.let { errorMessage ->
        Snackbar(
            modifier = Modifier.padding(16.dp),
            containerColor = Color(0xFF2D1B69),
            contentColor = Color.White,
            action = {
                TextButton(onClick = { viewModel.dismissError() }) {
                    Text("Закрыть", color = Color(0xFF7C6CFF))
                }
            }
        ) {
            Text(errorMessage)
        }
    }
}

@Composable
fun PowerButton(
    isConnected: Boolean,
    isConnecting: Boolean,
    onClick: () -> Unit
) {
    val infiniteTransition = rememberInfiniteTransition(label = "pulse")

    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.15f,
        targetValue = 0.4f,
        animationSpec = infiniteRepeatable(
            animation = tween(1500, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseAlpha"
    )

    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 1.2f,
        animationSpec = infiniteRepeatable(
            animation = tween(1500, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseScale"
    )

    val rotation by rememberInfiniteTransition(label = "rotation").animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(6000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "rotation"
    )

    val buttonColor = when {
        isConnected -> Color(0xFF00E676)
        isConnecting -> Color(0xFFFFAB00)
        else -> Color(0xFF7C6CFF)
    }

    Box(
        modifier = Modifier.size(180.dp),
        contentAlignment = Alignment.Center
    ) {
        // Outer pulse
        if (isConnected || isConnecting) {
            Canvas(modifier = Modifier.fillMaxSize()) {
                val scale = pulseScale
                drawCircle(
                    color = buttonColor.copy(alpha = pulseAlpha * 0.2f),
                    radius = size.minDimension / 2 * scale
                )
            }
        }

        // Rotating dots ring
        Canvas(modifier = Modifier.fillMaxSize()) {
            val radius = size.minDimension / 2 - 8.dp.toPx()
            for (i in 0..15) {
                val angle = Math.toRadians((i * 22.5 + rotation).toDouble())
                val x = center.x + radius * cos(angle).toFloat()
                val y = center.y + radius * sin(angle).toFloat()
                drawCircle(
                    color = buttonColor.copy(alpha = 0.4f + (if (isConnected) 0.3f else 0f)),
                    radius = 2.dp.toPx(),
                    center = Offset(x, y)
                )
            }
        }

        // Main circle
        Box(
            modifier = Modifier
                .size(140.dp)
                .shadow(
                    elevation = if (isConnected) 32.dp else 16.dp,
                    shape = CircleShape,
                    ambientColor = buttonColor.copy(alpha = 0.5f),
                    spotColor = buttonColor
                )
                .clip(CircleShape)
                .background(
                    Brush.radialGradient(
                        colors = listOf(
                            buttonColor.copy(alpha = 0.2f),
                            buttonColor.copy(alpha = 0.05f),
                            Color.Transparent
                        )
                    )
                )
                .clickable { onClick() },
            contentAlignment = Alignment.Center
        ) {
            Box(
                modifier = Modifier
                    .size(110.dp)
                    .shadow(
                        elevation = 12.dp,
                        shape = CircleShape,
                        ambientColor = buttonColor
                    )
                    .clip(CircleShape)
                    .background(
                        Brush.verticalGradient(
                            colors = listOf(
                                buttonColor,
                                buttonColor.copy(alpha = 0.7f)
                            )
                        )
                    ),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = when {
                        isConnecting -> Icons.Filled.Sync
                        isConnected -> Icons.Filled.Link
                        else -> Icons.Filled.PowerSettingsNew
                    },
                    contentDescription = if (isConnected) "Отключить" else "Подключить",
                    tint = Color.White,
                    modifier = Modifier.size(44.dp)
                )
            }
        }
    }
}

@Composable
fun ServerCard(
    server: VPNServer,
    isSelected: Boolean,
    onClick: () -> Unit,
    onPingClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 4.dp)
            .clickable { onClick() },
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isSelected)
                Color(0xFF7C6CFF).copy(alpha = 0.15f)
            else
                Color.White.copy(alpha = 0.05f)
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Flag
            Text(
                text = server.flag,
                fontSize = 28.sp
            )

            Spacer(modifier = Modifier.width(12.dp))

            // Info
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = server.name,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = Color.White,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "${server.protocol.displayName} • ${server.country}",
                    fontSize = 12.sp,
                    color = Color.White.copy(alpha = 0.5f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            // Ping
            if (server.ping >= 0) {
                val pingColor = when {
                    server.ping < 100 -> Color(0xFF00E676)
                    server.ping < 300 -> Color(0xFFFFAB00)
                    else -> Color(0xFFFF6B6B)
                }
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = pingColor.copy(alpha = 0.15f)
                ) {
                    Text(
                        text = "${server.ping}ms",
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium,
                        color = pingColor
                    )
                }
            }

            // Select indicator
            if (isSelected) {
                Spacer(modifier = Modifier.width(8.dp))
                Icon(
                    Icons.Filled.Check,
                    contentDescription = "Выбран",
                    tint = Color(0xFF7C6CFF),
                    modifier = Modifier.size(20.dp)
                )
            }
        }
    }
}

@Composable
fun ProtocolChip(
    label: String,
    isSelected: Boolean,
    onClick: () -> Unit
) {
    Surface(
        modifier = Modifier.clickable { onClick() },
        shape = RoundedCornerShape(20.dp),
        color = if (isSelected) Color(0xFF7C6CFF) else Color.White.copy(alpha = 0.08f)
    ) {
        Text(
            text = label,
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 6.dp),
            fontSize = 13.sp,
            color = if (isSelected) Color.White else Color.White.copy(alpha = 0.6f)
        )
    }
}

@Composable
fun AddSubscriptionDialog(
    onDismiss: () -> Unit,
    onAdd: (String, String) -> Unit
) {
    var url by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Color(0xFF1A1145),
        titleContentColor = Color.White,
        textContentColor = Color.White.copy(alpha = 0.8f),
        title = {
            Text("Добавить подписку", fontWeight = FontWeight.Bold)
        },
        text = {
            Column {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Название") },
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = Color(0xFF7C6CFF),
                        unfocusedBorderColor = Color.White.copy(alpha = 0.2f),
                        focusedTextColor = Color.White,
                        unfocusedTextColor = Color.White,
                        cursorColor = Color(0xFF7C6CFF)
                    ),
                    singleLine = true
                )
                Spacer(modifier = Modifier.height(12.dp))
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text("Ссылка подписки") },
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = Color(0xFF7C6CFF),
                        unfocusedBorderColor = Color.White.copy(alpha = 0.2f),
                        focusedTextColor = Color.White,
                        unfocusedTextColor = Color.White,
                        cursorColor = Color(0xFF7C6CFF)
                    ),
                    singleLine = true
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Поддержка: VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC",
                    fontSize = 11.sp,
                    color = Color.White.copy(alpha = 0.4f)
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { onAdd(url.ifEmpty { "https://" }, name.ifEmpty { "Подписка" }) },
                enabled = url.isNotEmpty(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF7C6CFF)),
                shape = RoundedCornerShape(10.dp)
            ) {
                Text("Добавить")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Отмена", color = Color.White.copy(alpha = 0.6f))
            }
        }
    )
}

@Composable
fun SettingsDialog(
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Color(0xFF1A1145),
        titleContentColor = Color.White,
        textContentColor = Color.White.copy(alpha = 0.8f),
        title = {
            Text("Настройки", fontWeight = FontWeight.Bold)
        },
        text = {
            Text(
                text = "QuantumVPN v1.0.0\n\nПоддерживаемые протоколы:\nVLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, WireGuard",
                fontSize = 14.sp,
                lineHeight = 22.sp
            )
        },
        confirmButton = {
            Button(
                onClick = onDismiss,
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF7C6CFF)),
                shape = RoundedCornerShape(10.dp)
            ) {
                Text("Закрыть")
            }
        },
        dismissButton = null
    )
}
