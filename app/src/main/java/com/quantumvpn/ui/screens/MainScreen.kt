package com.quantumvpn.ui.screens

import androidx.compose.animation.*
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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.lifecycle.viewmodel.compose.viewModel
import com.quantumvpn.data.*
import com.quantumvpn.ui.components.*
import com.quantumvpn.viewmodel.MainViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    viewModel: MainViewModel = viewModel()
) {
    val vpnState by viewModel.vpnState.collectAsState()
    val servers by viewModel.servers.collectAsState()
    val subscriptions by viewModel.subscriptions.collectAsState()
    val connectionState by viewModel.connectionState.collectAsState()
    val showAddSubscription by viewModel.showAddSubscription.collectAsState()
    val error by viewModel.error.collectAsState()
    val autoConnect by viewModel.autoConnect.collectAsState()
    val selectedProtocol by viewModel.selectedProtocol.collectAsState()

    var showServerList by remember { mutableStateOf(false) }
    var showSettings by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Filled.Shield,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(28.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "QuantumVPN",
                            fontWeight = FontWeight.Bold
                        )
                    }
                },
                actions = {
                    IconButton(onClick = { showSettings = true }) {
                        Icon(
                            imageVector = Icons.Outlined.Settings,
                            contentDescription = "Settings"
                        )
                    }
                    IconButton(onClick = { viewModel.refreshSubscriptions() }) {
                        Icon(
                            imageVector = Icons.Outlined.Refresh,
                            contentDescription = "Refresh"
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent
                )
            )
        }
    ) { paddingValues ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .background(
                    Brush.verticalGradient(
                        colors = listOf(
                            MaterialTheme.colorScheme.background,
                            MaterialTheme.colorScheme.surface,
                            MaterialTheme.colorScheme.background
                        )
                    )
                )
        ) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(bottom = 100.dp)
            ) {
                // Connection Status
                item {
                    Spacer(modifier = Modifier.height(24.dp))
                    StatusCard(vpnState = vpnState)
                }

                // Power Button
                item {
                    Spacer(modifier = Modifier.height(32.dp))
                    Box(
                        modifier = Modifier.fillMaxWidth(),
                        contentAlignment = Alignment.Center
                    ) {
                        PowerButton(
                            isConnected = vpnState.isConnected,
                            isConnecting = vpnState.isConnecting,
                            onClick = { viewModel.toggleConnection() }
                        )
                    }
                }

                // Server Selection
                item {
                    Spacer(modifier = Modifier.height(32.dp))
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp)
                            .clickable { showServerList = true },
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
                        )
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = vpnState.currentServer?.flag ?: "🌐",
                                fontSize = 36.sp
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = vpnState.currentServer?.name ?: "Select Server",
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Text(
                                    text = vpnState.currentServer?.let {
                                        "${it.country} • ${it.protocol.displayName}"
                                    } ?: "Tap to choose a server",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            Icon(
                                imageVector = Icons.Filled.ChevronRight,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }

                // Quick Stats
                item {
                    Spacer(modifier = Modifier.height(16.dp))
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
                        )
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            horizontalArrangement = Arrangement.SpaceEvenly
                        ) {
                            StatItem(
                                icon = Icons.Outlined.SignalCellularAlt,
                                label = "Ping",
                                value = vpnState.currentServer?.let {
                                    if (it.ping >= 0) "${it.ping}ms" else "---"
                                } ?: "---"
                            )
                            StatItem(
                                icon = Icons.Outlined.CloudDownload,
                                label = "Download",
                                value = formatSpeed(vpnState.downloadSpeed)
                            )
                            StatItem(
                                icon = Icons.Outlined.CloudUpload,
                                label = "Upload",
                                value = formatSpeed(vpnState.uploadSpeed)
                            )
                        }
                    }
                }

                // Protocol Filter
                item {
                    Spacer(modifier = Modifier.height(16.dp))
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        ProtocolChip(
                            label = "All",
                            isSelected = selectedProtocol == null,
                            onClick = { viewModel.filterByProtocol(null) }
                        )
                        Protocol.entries.take(4).forEach { protocol ->
                            ProtocolChip(
                                label = protocol.displayName,
                                isSelected = selectedProtocol == protocol,
                                onClick = { viewModel.filterByProtocol(protocol) }
                            )
                        }
                    }
                }

                // Server List
                val filteredServers = if (selectedProtocol != null) {
                    servers.filter { it.protocol == selectedProtocol }
                } else {
                    servers
                }

                if (filteredServers.isNotEmpty()) {
                    items(filteredServers) { server ->
                        ServerItem(
                            name = server.name,
                            country = server.country,
                            countryCode = server.countryCode,
                            flag = server.flag,
                            protocol = server.protocol.displayName,
                            ping = server.ping,
                            isSelected = server.id == vpnState.currentServer?.id,
                            onClick = { viewModel.selectServer(server) },
                            onPingClick = { viewModel.testPing(server) },
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
                        )
                    }
                } else {
                    item {
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
                            )
                        ) {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(32.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Icon(
                                    imageVector = Icons.Outlined.CloudOff,
                                    contentDescription = null,
                                    modifier = Modifier.size(48.dp),
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    text = "No servers available",
                                    style = MaterialTheme.typography.titleMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Text(
                                    text = "Add a subscription to get started",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                                )
                                Spacer(modifier = Modifier.height(16.dp))
                                Button(
                                    onClick = { viewModel.showAddSubscription(true) }
                                ) {
                                    Icon(
                                        imageVector = Icons.Filled.Add,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp)
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Add Subscription")
                                }
                            }
                        }
                    }
                }
            }

            // FAB for adding subscription
            FloatingActionButton(
                onClick = { viewModel.showAddSubscription(true) },
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(16.dp),
                containerColor = MaterialTheme.colorScheme.primary
            ) {
                Icon(
                    imageVector = Icons.Filled.Add,
                    contentDescription = "Add Subscription",
                    tint = Color.White
                )
            }
        }
    }

    // Add Subscription Dialog
    if (showAddSubscription) {
        AddSubscriptionDialog(
            onDismiss = { viewModel.showAddSubscription(false) },
            onAdd = { url, name -> viewModel.addSubscription(url, name) }
        )
    }

    // Server List Dialog
    if (showServerList) {
        ServerListDialog(
            servers = servers,
            selectedServerId = vpnState.currentServer?.id,
            onSelect = { server ->
                viewModel.selectServer(server)
                showServerList = false
            },
            onDismiss = { showServerList = false },
            onPingClick = { viewModel.testPing(it) },
            onTestAllPings = { viewModel.testAllPings() }
        )
    }

    // Settings Dialog
    if (showSettings) {
        SettingsDialog(
            autoConnect = autoConnect,
            onAutoConnectChange = { viewModel.setAutoConnect(it) },
            onDismiss = { showSettings = false }
        )
    }

    // Error Snackbar
    error?.let { errorMessage ->
        Snackbar(
            modifier = Modifier.padding(16.dp),
            action = {
                TextButton(onClick = { viewModel.dismissError() }) {
                    Text("Dismiss")
                }
            }
        ) {
            Text(errorMessage)
        }
    }
}

@Composable
fun ProtocolChip(
    label: String,
    isSelected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier.clickable { onClick() },
        shape = RoundedCornerShape(20.dp),
        color = if (isSelected) {
            MaterialTheme.colorScheme.primary
        } else {
            MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
        }
    ) {
        Text(
            text = label,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
            style = MaterialTheme.typography.labelMedium,
            color = if (isSelected) {
                MaterialTheme.colorScheme.onPrimary
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant
            }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ServerListDialog(
    servers: List<VPNServer>,
    selectedServerId: String?,
    onSelect: (VPNServer) -> Unit,
    onDismiss: () -> Unit,
    onPingClick: (VPNServer) -> Unit,
    onTestAllPings: () -> Unit,
    modifier: Modifier = Modifier
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = modifier
                .fillMaxWidth()
                .fillMaxHeight(0.8f),
            shape = RoundedCornerShape(20.dp)
        ) {
            Column(modifier = Modifier.fillMaxSize()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Select Server",
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Row {
                        IconButton(onClick = onTestAllPings) {
                            Icon(
                                imageVector = Icons.Outlined.Speed,
                                contentDescription = "Test All Pings"
                            )
                        }
                        IconButton(onClick = onDismiss) {
                            Icon(
                                imageVector = Icons.Filled.Close,
                                contentDescription = "Close"
                            )
                        }
                    }
                }

                Divider()

                LazyColumn(
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(8.dp)
                ) {
                    items(servers) { server ->
                        ServerItem(
                            name = server.name,
                            country = server.country,
                            countryCode = server.countryCode,
                            flag = server.flag,
                            protocol = server.protocol.displayName,
                            ping = server.ping,
                            isSelected = server.id == selectedServerId,
                            onClick = { onSelect(server) },
                            onPingClick = { onPingClick(server) }
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun AddSubscriptionDialog(
    onDismiss: () -> Unit,
    onAdd: (String, String) -> Unit,
    modifier: Modifier = Modifier
) {
    var url by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }

    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(20.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp)
            ) {
                Text(
                    text = "Add Subscription",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(16.dp))

                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Name (optional)") },
                    modifier = Modifier.fillMaxWidth(),
                    leadingIcon = {
                        Icon(Icons.Outlined.Label, contentDescription = null)
                    }
                )

                Spacer(modifier = Modifier.height(12.dp))

                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text("Subscription URL") },
                    modifier = Modifier.fillMaxWidth(),
                    leadingIcon = {
                        Icon(Icons.Outlined.Link, contentDescription = null)
                    },
                    placeholder = { Text("https://example.com/sub") }
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "Supports: VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, WireGuard",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Spacer(modifier = Modifier.height(20.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = onDismiss) {
                        Text("Cancel")
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Button(
                        onClick = { onAdd(url.ifEmpty { "https://" }, name.ifEmpty { "Subscription" }) },
                        enabled = url.isNotEmpty()
                    ) {
                        Text("Add")
                    }
                }
            }
        }
    }
}

@Composable
fun SettingsDialog(
    autoConnect: Boolean,
    onAutoConnectChange: (Boolean) -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(20.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp)
            ) {
                Text(
                    text = "Settings",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(20.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Auto-connect on boot",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Text(
                            text = "Automatically connect to VPN when device starts",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(
                        checked = autoConnect,
                        onCheckedChange = onAutoConnectChange
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))
                Divider()
                Spacer(modifier = Modifier.height(16.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = onDismiss) {
                        Text("Close")
                    }
                }
            }
        }
    }
}

private fun formatSpeed(bytes: Long): String {
    return when {
        bytes < 1024 -> "$bytes B/s"
        bytes < 1024 * 1024 -> "${bytes / 1024} KB/s"
        else -> "${bytes / (1024 * 1024)} MB/s"
    }
}
