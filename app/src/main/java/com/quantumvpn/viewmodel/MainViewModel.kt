package com.quantumvpn.viewmodel

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.os.Build
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.quantumvpn.core.SubscriptionParser
import com.quantumvpn.core.VPNCore
import com.quantumvpn.data.*
import com.quantumvpn.service.VPNService
import com.quantumvpn.utils.UpdateChecker
import com.quantumvpn.BuildConfig
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
        .addInterceptor { chain ->
            chain.proceed(
                chain.request().newBuilder()
                    .header("User-Agent", "QuantumVPN/${BuildConfig.VERSION_NAME}")
                    .build()
            )
        }
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

    private val _infoMessage = MutableStateFlow<String?>(null)
    val infoMessage: StateFlow<String?> = _infoMessage.asStateFlow()

    private val _isRefreshing = MutableStateFlow(false)
    val isRefreshing: StateFlow<Boolean> = _isRefreshing.asStateFlow()

    private val _isPinging = MutableStateFlow(false)
    val isPinging: StateFlow<Boolean> = _isPinging.asStateFlow()

    private val _isCheckingUpdate = MutableStateFlow(false)
    val isCheckingUpdate: StateFlow<Boolean> = _isCheckingUpdate.asStateFlow()

    private val _updateRelease = MutableStateFlow<UpdateChecker.GitHubRelease?>(null)
    val updateRelease: StateFlow<UpdateChecker.GitHubRelease?> = _updateRelease.asStateFlow()

    private val _autoConnect = MutableStateFlow(prefs.getBoolean("auto_connect", false))
    val autoConnect: StateFlow<Boolean> = _autoConnect.asStateFlow()

    private val _selectedProtocol = MutableStateFlow<Protocol?>(null)
    val selectedProtocol: StateFlow<Protocol?> = _selectedProtocol.asStateFlow()

    private val vpnStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            val state = intent.getStringExtra("state") ?: return
            connectTimeoutJob?.cancel()
            when (state) {
                "connected" -> {
                    _vpnState.update { it.copy(isConnected = true, isConnecting = false, connectionTime = System.currentTimeMillis()) }
                    _connectionState.value = ConnectionState.Connected
                    startTrafficTracking()
                }
                "disconnected" -> {
                    _vpnState.update { it.copy(isConnected = false, isConnecting = false, connectionTime = 0L, totalDownload = 0L, totalUpload = 0L) }
                    _connectionState.value = ConnectionState.Disconnected
                    trafficJob?.cancel()
                }
                "error" -> {
                    val errorMsg = intent.getStringExtra("error") ?: "╨Ю╤И╨╕╨▒╨║╨░ ╨┐╨╛╨┤╨║╨╗╤О╤З╨╡╨╜╨╕╤П"
                    _vpnState.update { it.copy(isConnected = false, isConnecting = false) }
                    _connectionState.value = ConnectionState.Error(errorMsg)
                    _error.value = errorMsg
                }
            }
        }
    }

    init {
        loadSavedData()
        val filter = IntentFilter("com.quantumvpn.VPN_STATE")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(vpnStateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(vpnStateReceiver, filter)
        }
    }

    private fun loadSavedData() {
        viewModelScope.launch {
            try {
                val savedServers = ServerStorage.loadServers(context)
                val savedSubs = ServerStorage.loadSubscriptions(context)
                _servers.value = savedServers
                _subscriptions.value = savedSubs

                val selectedId = prefs.getString("selected_server_id", null)
                if (selectedId != null) {
                    savedServers.find { it.id == selectedId }?.let { server ->
                        _vpnState.update { it.copy(currentServer = server) }
                        CurrentServer.set(server)
                    }
                } else if (savedServers.isNotEmpty()) {
                    val first = savedServers.first()
                    _vpnState.update { it.copy(currentServer = first) }
                    CurrentServer.set(first)
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    private var trafficJob: Job? = null
    private var connectTimeoutJob: Job? = null
    private var saveJob: Job? = null

    private fun saveData() {
        saveJob?.cancel()
        saveJob = viewModelScope.launch {
            delay(300)
            try {
                val serversSnapshot = _servers.value
                val subsSnapshot = _subscriptions.value
                ServerStorage.saveAll(context, serversSnapshot, subsSnapshot)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    private fun serverKey(server: VPNServer): String =
        "${server.protocol.name}|${server.host}|${server.port}|${server.settings["uuid"] ?: server.settings["password"] ?: ""}"

    fun connectVPN() {
        val server = _vpnState.value.currentServer ?: run {
            _error.value = "╨Т╤Л╨▒╨╡╤А╨╕╤В╨╡ ╤Б╨╡╤А╨▓╨╡╤А ╨╕╨╖ ╤Б╨┐╨╕╤Б╨║╨░"
            return
        }

        viewModelScope.launch {
            _connectionState.value = ConnectionState.Connecting
            _vpnState.update { it.copy(isConnecting = true) }
            CurrentServer.set(server)

            connectTimeoutJob?.cancel()
            connectTimeoutJob = viewModelScope.launch {
                delay(30_000)
                if (_vpnState.value.isConnecting && !_vpnState.value.isConnected) {
                    _vpnState.update { it.copy(isConnecting = false) }
                    _connectionState.value = ConnectionState.Error("╨в╨░╨╣╨╝╨░╤Г╤В ╨┐╨╛╨┤╨║╨╗╤О╤З╨╡╨╜╨╕╤П")
                    _error.value = "╨Э╨╡ ╤Г╨┤╨░╨╗╨╛╤Б╤М ╨┐╨╛╨┤╨║╨╗╤О╤З╨╕╤В╤М╤Б╤П ╨╖╨░ 30 ╤Б╨╡╨║╤Г╨╜╨┤"
                }
            }

            try {
                val intent = Intent(context, VPNService::class.java).apply {
                    action = "com.quantumvpn.START"
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
            } catch (e: Exception) {
                connectTimeoutJob?.cancel()
                _vpnState.update { it.copy(isConnecting = false) }
                _connectionState.value = ConnectionState.Error(e.message ?: "╨Ю╤И╨╕╨▒╨║╨░ ╨┐╨╛╨┤╨║╨╗╤О╤З╨╡╨╜╨╕╤П")
                _error.value = e.message ?: "╨Ю╤И╨╕╨▒╨║╨░ ╨┐╨╛╨┤╨║╨╗╤О╤З╨╡╨╜╨╕╤П"
            }
        }
    }

    private fun startTrafficTracking() {
        trafficJob?.cancel()
        trafficJob = viewModelScope.launch {
            while (isActive) {
                delay(1000)
                _vpnState.update {
                    it.copy(
                        totalDownload = VPNCore.totalDownload,
                        totalUpload = VPNCore.totalUpload
                    )
                }
            }
        }
    }

    fun disconnectVPN() {
        connectTimeoutJob?.cancel()
        viewModelScope.launch {
            _connectionState.value = ConnectionState.Disconnecting
            try {
                val intent = Intent(context, VPNService::class.java).apply {
                    action = "com.quantumvpn.STOP"
                }
                context.startService(intent)
            } catch (e: Exception) {
                _connectionState.value = ConnectionState.Error(e.message ?: "╨Ю╤И╨╕╨▒╨║╨░ ╨╛╤В╨║╨╗╤О╤З╨╡╨╜╨╕╤П")
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
        _servers.update { list -> list.map { it.copy(isSelected = it.id == server.id) } }
        _vpnState.update { it.copy(currentServer = server) }
        CurrentServer.set(server)
        prefs.edit().putString("selected_server_id", server.id).apply()
    }

    fun addSubscription(url: String, name: String = "╨Я╨╛╨┤╨┐╨╕╤Б╨║╨░") {
        val trimmed = url.trim()
        if (trimmed.isEmpty()) {
            _error.value = "╨Т╨▓╨╡╨┤╨╕╤В╨╡ ╤Б╤Б╤Л╨╗╨║╤Г ╨╕╨╗╨╕ ╨║╨╛╨╜╤Д╨╕╨│"
            return
        }
        if (!trimmed.startsWith("http://", true) && !trimmed.startsWith("https://", true)) {
            importFromText(trimmed, name)
            return
        }
        viewModelScope.launch {
            try {
                val body = fetchSubscriptionBody(trimmed)
                val parsed = SubscriptionParser.parse(body)
                if (parsed.isEmpty()) throw Exception("╨б╨╡╤А╨▓╨╡╤А╤Л ╨╜╨╡ ╨╜╨░╨╣╨┤╨╡╨╜╤Л ╨▓ ╨┐╨╛╨┤╨┐╨╕╤Б╨║╨╡")

                val subscription = Subscription(
                    name = name,
                    url = trimmed,
                    servers = parsed,
                    lastUpdate = System.currentTimeMillis()
                )

                _subscriptions.update { it + subscription }
                _servers.update { current -> mergeServers(current, parsed) }
                parsed.firstOrNull()?.let { selectServer(it) }
                _showAddSubscription.value = false
                _infoMessage.value = "╨Ф╨╛╨▒╨░╨▓╨╗╨╡╨╜╨╛ ╤Б╨╡╤А╨▓╨╡╤А╨╛╨▓: ${parsed.size}"
                saveData()
            } catch (e: Exception) {
                _error.value = "╨Ю╤И╨╕╨▒╨║╨░ ╨┐╨╛╨┤╨┐╨╕╤Б╨║╨╕: ${e.message}"
            }
        }
    }

    fun importFromText(text: String, name: String = "╨Ш╨╝╨┐╨╛╤А╤В") {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) {
            _error.value = "╨Я╤Г╤Б╤В╨╛╨╣ ╤В╨╡╨║╤Б╤В"
            return
        }

        if (trimmed.startsWith("http://", true) || trimmed.startsWith("https://", true)) {
            addSubscription(trimmed, name)
            return
        }

        viewModelScope.launch {
            try {
                val parsed = SubscriptionParser.parse(trimmed)
                if (parsed.isEmpty()) throw Exception("╨Э╨╡ ╤Г╨┤╨░╨╗╨╛╤Б╤М ╤А╨░╤Б╨┐╨╛╨╖╨╜╨░╤В╤М ╨║╨╛╨╜╤Д╨╕╨│")

                _servers.update { current -> mergeServers(current, parsed) }
                parsed.firstOrNull()?.let { selectServer(it) }
                _showAddSubscription.value = false
                _infoMessage.value = "╨Ш╨╝╨┐╨╛╤А╤В╨╕╤А╨╛╨▓╨░╨╜╨╛ ╤Б╨╡╤А╨▓╨╡╤А╨╛╨▓: ${parsed.size}"
                saveData()
            } catch (e: Exception) {
                _error.value = "╨Ю╤И╨╕╨▒╨║╨░ ╨╕╨╝╨┐╨╛╤А╤В╨░: ${e.message}"
            }
        }
    }

    fun importFromClipboard() {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        val clip = cm.primaryClip
        if (clip == null || clip.itemCount == 0) {
            _error.value = "╨С╤Г╤Д╨╡╤А ╨╛╨▒╨╝╨╡╨╜╨░ ╨┐╤Г╤Б╤В"
            return
        }
        val text = clip.getItemAt(0).coerceToText(context)?.toString()?.trim() ?: ""
        if (text.isEmpty()) {
            _error.value = "╨С╤Г╤Д╨╡╤А ╨╛╨▒╨╝╨╡╨╜╨░ ╨┐╤Г╤Б╤В"
            return
        }
        importFromText(text, "╨Ш╨╖ ╨▒╤Г╤Д╨╡╤А╨░")
    }

    fun refreshSubscriptions() {
        if (_subscriptions.value.isEmpty()) {
            _error.value = "╨Э╨╡╤В ╨┐╨╛╨┤╨┐╨╕╤Б╨╛╨║. ╨Ф╨╛╨▒╨░╨▓╤М╤В╨╡ ╨┐╨╛╨┤╨┐╨╕╤Б╨║╤Г ╨┐╨╛ ╤Б╤Б╤Л╨╗╨║╨╡"
            return
        }
        if (_isRefreshing.value) return

        viewModelScope.launch {
            _isRefreshing.value = true
            try {
                val updatedSubs = mutableListOf<Subscription>()
                val updatedFromSubs = mutableListOf<VPNServer>()
                var errors = 0

                _subscriptions.value.forEach { sub ->
                    try {
                        val body = fetchSubscriptionBody(sub.url)
                        val parsed = SubscriptionParser.parse(body)
                        if (parsed.isEmpty()) throw Exception("╨б╨╡╤А╨▓╨╡╤А╤Л ╨╜╨╡ ╨╜╨░╨╣╨┤╨╡╨╜╤Л")
                        updatedSubs.add(sub.copy(servers = parsed, lastUpdate = System.currentTimeMillis()))
                        updatedFromSubs.addAll(parsed)
                    } catch (e: Exception) {
                        errors++
                        updatedSubs.add(sub)
                        e.printStackTrace()
                    }
                }

                if (updatedFromSubs.isNotEmpty()) {
                    val subKeys = updatedFromSubs.map { serverKey(it) }.toSet()
                    val standalone = _servers.value.filter { serverKey(it) !in subKeys }
                    _subscriptions.value = updatedSubs
                    _servers.value = mergeServers(standalone, updatedFromSubs)

                    val current = _vpnState.value.currentServer
                    val newCurrent = if (current != null) {
                        _servers.value.find { it.id == current.id }
                            ?: _servers.value.find { serverKey(it) == serverKey(current) }
                            ?: _servers.value.firstOrNull()
                    } else {
                        _servers.value.firstOrNull()
                    }
                    newCurrent?.let { selectServer(it) }

                    _infoMessage.value = if (errors > 0) {
                        "╨Ю╨▒╨╜╨╛╨▓╨╗╨╡╨╜╨╛ ${updatedFromSubs.size} ╤Б╨╡╤А╨▓╨╡╤А╨╛╨▓ (╤З╨░╤Б╤В╨╕╤З╨╜╨╛)"
                    } else {
                        "╨Ю╨▒╨╜╨╛╨▓╨╗╨╡╨╜╨╛ ╤Б╨╡╤А╨▓╨╡╤А╨╛╨▓: ${updatedFromSubs.size}"
                    }
                    saveData()
                } else {
                    _error.value = "╨Э╨╡ ╤Г╨┤╨░╨╗╨╛╤Б╤М ╨╛╨▒╨╜╨╛╨▓╨╕╤В╤М ╨┐╨╛╨┤╨┐╨╕╤Б╨║╨╕"
                }
            } catch (e: Exception) {
                _error.value = "╨Ю╤И╨╕╨▒╨║╨░ ╨╛╨▒╨╜╨╛╨▓╨╗╨╡╨╜╨╕╤П: ${e.message}"
            } finally {
                _isRefreshing.value = false
            }
        }
    }

    private suspend fun fetchSubscriptionBody(url: String): String = withContext(Dispatchers.IO) {
        val request = Request.Builder().url(url).build()
        val response = client.newCall(request).execute()
        if (!response.isSuccessful) throw Exception("HTTP ${response.code}")
        response.body?.string() ?: throw Exception("╨Я╤Г╤Б╤В╨╛╨╣ ╨╛╤В╨▓╨╡╤В")
    }

    private fun mergeServers(existing: List<VPNServer>, incoming: List<VPNServer>): List<VPNServer> {
        val result = existing.toMutableList()
        val indexByKey = result.mapIndexed { index, server -> serverKey(server) to index }.toMap().toMutableMap()
        for (server in incoming) {
            val key = serverKey(server)
            val existingIndex = indexByKey[key]
            if (existingIndex != null) {
                val old = result[existingIndex]
                result[existingIndex] = server.copy(id = old.id, ping = old.ping, isSelected = old.isSelected)
            } else {
                indexByKey[key] = result.size
                result.add(server)
            }
        }
        return result
    }

    fun removeSubscription(subscription: Subscription) {
        val removeIds = subscription.servers.map { it.id }.toSet()
        _subscriptions.update { current -> current.filter { it.id != subscription.id } }
        _servers.update { current -> current.filter { it.id !in removeIds } }
        if (_vpnState.value.currentServer?.id in removeIds) {
            _servers.value.firstOrNull()?.let { selectServer(it) }
        }
        saveData()
    }

    fun testPing(server: VPNServer) {
        viewModelScope.launch {
            _servers.update { list -> list.map { if (it.id == server.id) it.copy(ping = -2L) else it } }
            val ping = withContext(Dispatchers.IO) {
                VPNCore.testPing(server.host, server.port)
            }
            _servers.update { list -> list.map { if (it.id == server.id) it.copy(ping = ping) else it } }
        }
    }

    fun testAllPings() {
        if (_servers.value.isEmpty()) {
            _error.value = "╨Э╨╡╤В ╤Б╨╡╤А╨▓╨╡╤А╨╛╨▓ ╨┤╨╗╤П ╨┐╤А╨╛╨▓╨╡╤А╨║╨╕"
            return
        }
        if (_isPinging.value) return

        viewModelScope.launch {
            _isPinging.value = true
            try {
                val currentServers = _servers.value
                _servers.update { list -> list.map { it.copy(ping = -2L) } }

                val updatedServers = withContext(Dispatchers.IO) {
                    currentServers.map { server ->
                        val ping = VPNCore.testPing(server.host, server.port)
                        server.copy(ping = ping)
                    }
                }

                _servers.value = updatedServers
                val ok = updatedServers.count { it.ping >= 0 }
                _infoMessage.value = "╨Я╨╕╨╜╨│: $ok/${updatedServers.size} ╤Б╨╡╤А╨▓╨╡╤А╨╛╨▓ ╨╛╤В╨▓╨╡╤З╨░╤О╤В"
            } catch (e: Exception) {
                _error.value = "╨Ю╤И╨╕╨▒╨║╨░ ╨┐╨╕╨╜╨│╨░: ${e.message}"
            } finally {
                _isPinging.value = false
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

    fun filteredServers(): List<VPNServer> {
        val protocol = _selectedProtocol.value
        return if (protocol == null) _servers.value else _servers.value.filter { it.protocol == protocol }
    }

    fun checkForAppUpdate() {
        viewModelScope.launch {
            _isCheckingUpdate.value = true
            try {
                val release = UpdateChecker.checkForUpdate(BuildConfig.VERSION_NAME)
                if (release != null) {
                    _updateRelease.value = release
                    _infoMessage.value = "╨Ф╨╛╤Б╤В╤Г╨┐╨╜╨░ ╨▓╨╡╤А╤Б╨╕╤П ${release.tag_name}"
                } else {
                    _infoMessage.value = "╨г ╨▓╨░╤Б ╨┐╨╛╤Б╨╗╨╡╨┤╨╜╤П╤П ╨▓╨╡╤А╤Б╨╕╤П (${BuildConfig.VERSION_NAME})"
                }
            } catch (e: Exception) {
                _error.value = "╨Э╨╡ ╤Г╨┤╨░╨╗╨╛╤Б╤М ╨┐╤А╨╛╨▓╨╡╤А╨╕╤В╤М ╨╛╨▒╨╜╨╛╨▓╨╗╨╡╨╜╨╕╤П: ${e.message}"
            } finally {
                _isCheckingUpdate.value = false
            }
        }
    }

    fun downloadUpdate() {
        val release = _updateRelease.value ?: return
        val apk = release.assets.firstOrNull { it.name.endsWith(".apk") } ?: return
        viewModelScope.launch {
            _infoMessage.value = "╨б╨║╨░╤З╨╕╨▓╨░╨╜╨╕╨╡ ╨╛╨▒╨╜╨╛╨▓╨╗╨╡╨╜╨╕╤П..."
            val ok = UpdateChecker.downloadAndInstall(context, apk)
            if (!ok) _error.value = "╨Э╨╡ ╤Г╨┤╨░╨╗╨╛╤Б╤М ╤Б╨║╨░╤З╨░╤В╤М ╨╛╨▒╨╜╨╛╨▓╨╗╨╡╨╜╨╕╨╡"
        }
    }

    fun dismissUpdate() {
        _updateRelease.value = null
    }

    fun showError(message: String) {
        _error.value = message
    }

    fun dismissError() {
        _error.value = null
    }

    fun dismissInfo() {
        _infoMessage.value = null
    }

    fun showAddSubscription(show: Boolean) {
        _showAddSubscription.value = show
    }

    override fun onCleared() {
        super.onCleared()
        connectTimeoutJob?.cancel()
        try { context.unregisterReceiver(vpnStateReceiver) } catch (_: Exception) {}
    }
}
