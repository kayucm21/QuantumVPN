package com.quantumvpn.viewmodel

import android.app.Application
import android.content.Intent
import android.content.SharedPreferences
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.quantumvpn.core.SubscriptionParser
import com.quantumvpn.core.VPNCore
import com.quantumvpn.data.*
import com.quantumvpn.service.VPNService
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

class MainViewModel(application: Application) : AndroidViewModel(application) {
    private val context = application
    private val prefs: SharedPreferences = application.getSharedPreferences("vpn_prefs", 0)
    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    private val _vpnState = MutableStateFlow(VPNState())
    val vpnState: StateFlow<VPNState> = _vpnState.asStateFlow()

    private val _servers = MutableStateFlow<List<VPNServer>>(emptyList())
    val servers: StateFlow<List<VPNServer>> = _servers.asStateFlow()

    private val _subscriptions = MutableStateFlow<List<Subscription>>(emptyList())
    val subscriptions: StateFlow<List<Subscription>> = _subscriptions.asStateFlow()

    private val _connectionState = MutableStateFlow<ConnectionState>(ConnectionState.Disconnected)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    private val _showAddSubscription = MutableStateFlow(false)
    val showAddSubscription: StateFlow<Boolean> = _showAddSubscription.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    private val _autoConnect = MutableStateFlow(prefs.getBoolean("auto_connect", false))
    val autoConnect: StateFlow<Boolean> = _autoConnect.asStateFlow()

    private val _selectedProtocol = MutableStateFlow<Protocol?>(null)
    val selectedProtocol: StateFlow<Protocol?> = _selectedProtocol.asStateFlow()

    init {
        loadSavedData()
    }

    private fun loadSavedData() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val serversFile = java.io.File(context.filesDir, "servers.json")
                if (serversFile.exists()) {
                    val json = serversFile.readText()
                    val type = object : com.google.gson.reflect.TypeToken<List<VPNServer>>() {}.type
                    val savedServers = com.google.gson.Gson().fromJson<List<VPNServer>>(json, type)
                    _servers.value = savedServers ?: emptyList()
                }

                val subsFile = java.io.File(context.filesDir, "subscriptions.json")
                if (subsFile.exists()) {
                    val json = subsFile.readText()
                    val type = object : com.google.gson.reflect.TypeToken<List<Subscription>>() {}.type
                    val savedSubs = com.google.gson.Gson().fromJson<List<Subscription>>(json, type)
                    _subscriptions.value = savedSubs ?: emptyList()
                }

                val selectedId = prefs.getString("selected_server_id", null)
                if (selectedId != null) {
                    _servers.value.find { it.id == selectedId }?.let { server ->
                        _vpnState.update { it.copy(currentServer = server) }
                    }
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    fun connectVPN() {
        val server = _vpnState.value.currentServer ?: run {
            _error.value = "No server selected"
            return
        }

        viewModelScope.launch {
            _connectionState.value = ConnectionState.Connecting
            _vpnState.update { it.copy(isConnecting = true) }

            try {
                val intent = Intent(context, VPNService::class.java).apply {
                    action = "com.quantumvpn.START"
                }
                context.startForegroundService(intent)

                _vpnState.update {
                    it.copy(
                        isConnected = true,
                        isConnecting = false,
                        connectionTime = System.currentTimeMillis()
                    )
                }
                _connectionState.value = ConnectionState.Connected
            } catch (e: Exception) {
                _vpnState.update { it.copy(isConnecting = false) }
                _connectionState.value = ConnectionState.Error(e.message ?: "Connection failed")
                _error.value = e.message
            }
        }
    }

    fun disconnectVPN() {
        viewModelScope.launch {
            _connectionState.value = ConnectionState.Disconnecting

            try {
                val intent = Intent(context, VPNService::class.java).apply {
                    action = "com.quantumvpn.STOP"
                }
                context.startService(intent)

                _vpnState.update {
                    it.copy(
                        isConnected = false,
                        isConnecting = false,
                        connectionTime = 0L,
                        downloadSpeed = 0L,
                        uploadSpeed = 0L
                    )
                }
                _connectionState.value = ConnectionState.Disconnected
            } catch (e: Exception) {
                _connectionState.value = ConnectionState.Error(e.message ?: "Disconnect failed")
            }
        }
    }

    fun toggleConnection() {
        if (_vpnState.value.isConnected) {
            disconnectVPN()
        } else {
            connectVPN()
        }
    }

    fun selectServer(server: VPNServer) {
        _servers.value = _servers.value.map {
            it.copy(isSelected = it.id == server.id)
        }
        _vpnState.update { it.copy(currentServer = server) }
        prefs.edit().putString("selected_server_id", server.id).apply()
    }

    fun addSubscription(url: String, name: String = "Subscription") {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val request = Request.Builder().url(url).build()
                val response = client.newCall(request).execute()
                val body = response.body?.string() ?: throw Exception("Empty response")

                val servers = SubscriptionParser.parse(body)
                val subscription = Subscription(
                    name = name,
                    url = url,
                    servers = servers,
                    lastUpdate = System.currentTimeMillis()
                )

                _subscriptions.update { current -> current + subscription }
                _servers.update { current -> current + servers }

                saveData()
                _showAddSubscription.value = false
            } catch (e: Exception) {
                _error.value = "Failed to add subscription: ${e.message}"
            }
        }
    }

    fun refreshSubscriptions() {
        viewModelScope.launch(Dispatchers.IO) {
            val updatedServers = mutableListOf<VPNServer>()

            _subscriptions.value.forEach { sub ->
                try {
                    val request = Request.Builder().url(sub.url).build()
                    val response = client.newCall(request).execute()
                    val body = response.body?.string() ?: return@forEach

                    val servers = SubscriptionParser.parse(body)
                    updatedServers.addAll(servers)
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }

            _servers.value = updatedServers
            saveData()
        }
    }

    fun removeSubscription(subscription: Subscription) {
        _subscriptions.update { current -> current.filter { it.id != subscription.id } }
        _servers.update { current -> current.filter { it !in subscription.servers } }
        saveData()
    }

    fun testPing(server: VPNServer) {
        viewModelScope.launch(Dispatchers.IO) {
            val ping = VPNCore.testPing(server.host, server.port)
            _servers.value = _servers.value.map {
                if (it.id == server.id) it.copy(ping = ping) else it
            }
        }
    }

    fun testAllPings() {
        viewModelScope.launch(Dispatchers.IO) {
            _servers.value.forEach { server ->
                testPing(server)
            }
        }
    }

    fun setAutoConnect(enabled: Boolean) {
        _autoConnect.value = enabled
        prefs.edit().putBoolean("auto_connect", enabled).apply()
    }

    fun filterByProtocol(protocol: Protocol?) {
        _selectedProtocol.value = protocol
    }

    fun showError(message: String) {
        _error.value = message
    }

    fun dismissError() {
        _error.value = null
    }

    fun showAddSubscription(show: Boolean) {
        _showAddSubscription.value = show
    }

    private fun saveData() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val serversFile = java.io.File(context.filesDir, "servers.json")
                serversFile.writeText(com.google.gson.Gson().toJson(_servers.value))

                val subsFile = java.io.File(context.filesDir, "subscriptions.json")
                subsFile.writeText(com.google.gson.Gson().toJson(_subscriptions.value))
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        viewModelScope.cancel()
    }
}
