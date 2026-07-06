package com.quantumvpn.data

import java.util.UUID

data class VPNServer(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val country: String,
    val countryCode: String,
    val flag: String,
    val host: String,
    val port: Int,
    val protocol: Protocol,
    val settings: Map<String, Any> = emptyMap(),
    val ping: Long = -1L,
    val isSelected: Boolean = false
)

enum class Protocol(val displayName: String) {
    VLESS("VLESS"),
    VMESS("VMess"),
    TROJAN("Trojan"),
    SHADOWSOCKS("Shadowsocks"),
    WIREGUARD("WireGuard"),
    Hysteria2("Hysteria2"),
    TUIC("TUIC")
}

data class Subscription(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val url: String,
    val servers: List<VPNServer> = emptyList(),
    val lastUpdate: Long = System.currentTimeMillis()
)

data class VPNState(
    val isConnected: Boolean = false,
    val isConnecting: Boolean = false,
    val currentServer: VPNServer? = null,
    val connectionTime: Long = 0L,
    val downloadSpeed: Long = 0L,
    val uploadSpeed: Long = 0L,
    val totalDownload: Long = 0L,
    val totalUpload: Long = 0L
)

sealed class ConnectionState {
    data object Disconnected : ConnectionState()
    data object Connecting : ConnectionState()
    data object Connected : ConnectionState()
    data object Disconnecting : ConnectionState()
    data class Error(val message: String) : ConnectionState()
}
