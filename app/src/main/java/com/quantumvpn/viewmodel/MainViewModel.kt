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
                    val errorMsg = intent.getStringExtra("error") ?: "Ошибка подключения"
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
                        CurrentServer.set(server)
                    }
                } else if (_servers.value.isNotEmpty()) {
                    val first = _servers.value.first()
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

    fun connectVPN() {
        val server = _vpnState.value.currentServer ?: run {
            _error.value = "Выберите сервер из списка"
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
                    _connectionState.value = ConnectionState.Error("Таймаут подключения")
                    _error.value = "Не удалось подключиться за 30 секунд"
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
                _connectionState.value = ConnectionState.Error(e.message ?: "Ошибка подключения")
                _error.value = e.message ?: "Ошибка подключения"
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
                _connectionState.value = ConnectionState.Error(e.message ?: "Ошибка отключения")
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
        CurrentServer.set(server)
        prefs.edit().putString("selected_server_id", server.id).apply()
    }

    fun addSubscription(url: String, name: String = "Подписка") {
        val trimmed = url.trim()
        if (trimmed.isEmpty()) {
            _error.value = "Введите ссылку или конфиг"
            return
        }
        if (!trimmed.startsWith("http://", true) && !trimmed.startsWith("https://", true)) {
            importFromText(trimmed, name)
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val request = Request.Builder().url(trimmed).build()
                val response = client.newCall(request).execute()
                if (!response.isSuccessful) throw Exception("HTTP ${response.code}")
                val body = response.body?.string() ?: throw Exception("Пустой ответ")

                val servers = SubscriptionParser.parse(body)
                if (servers.isEmpty()) throw Exception("Серверы не найдены в подписке")

                val subscription = Subscription(
                    name = name,
                    url = trimmed,
                    servers = servers,
                    lastUpdate = System.currentTimeMillis()
                )

                withContext(Dispatchers.Main) {
                    _subscriptions.update { current -> current + subscription }
                    _servers.update { current -> current + servers }
                    servers.firstOrNull()?.let { selectServer(it) }
                    _showAddSubscription.value = false
                    _infoMessage.value = "Добавлено серверов: ${servers.size}"
                }
                saveData()
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    _error.value = "Ошибка подписки: ${e.message}"
                }
            }
        }
    }

    fun importFromText(text: String, name: String = "Импорт") {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) {
            _error.value = "Пустой текст"
            return
        }

        if (trimmed.startsWith("http://", true) || trimmed.startsWith("https://", true)) {
            addSubscription(trimmed, name)
            return
        }

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val servers = SubscriptionParser.parse(trimmed)
                if (servers.isEmpty()) throw Exception("Не удалось распознать конфиг")

                withContext(Dispatchers.Main) {
                    _servers.update { current -> current + servers }
                    servers.firstOrNull()?.let { selectServer(it) }
                    _showAddSubscription.value = false
                    _infoMessage.value = "Импортировано серверов: ${servers.size}"
                }
                saveData()
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    _error.value = "Ошибка импорта: ${e.message}"
                }
            }
        }
    }

    fun importFromClipboard() {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        val clip = cm.primaryClip
        if (clip == null || clip.itemCount == 0) {
            _error.value = "Буфер обмена пуст"
            return
        }
        val text = clip.getItemAt(0).coerceToText(context)?.toString()?.trim() ?: ""
        if (text.isEmpty()) {
            _error.value = "Буфер обмена пуст"
            return
        }
        importFromText(text, "Из буфера")
    }

    fun refreshSubscriptions() {
        if (_subscriptions.value.isEmpty()) {
            _error.value = "Нет подписок. Добавьте подписку по ссылке"
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            _isRefreshing.value = true
            val updatedSubs = mutableListOf<Subscription>()
            val updatedServers = mutableListOf<VPNServer>()
            var errors = 0

            _subscriptions.value.forEach { sub ->
                try {
                    val request = Request.Builder().url(sub.url).build()
                    val response = client.newCall(request).execute()
                    if (!response.isSuccessful) throw Exception("HTTP ${response.code}")
                    val body = response.body?.string() ?: throw Exception("Пустой ответ")
                    val servers = SubscriptionParser.parse(body)
                    if (servers.isEmpty()) throw Exception("Серверы не найдены")
                    updatedSubs.add(sub.copy(servers = servers, lastUpdate = System.currentTimeMillis()))
                    updatedServers.addAll(servers)
                } catch (e: Exception) {
                    errors++
                    updatedSubs.add(sub)
                    e.printStackTrace()
                }
            }

            withContext(Dispatchers.Main) {
                _isRefreshing.value = false
                if (updatedServers.isNotEmpty()) {
                    _subscriptions.value = updatedSubs
                    _servers.value = updatedServers
                    val selectedId = _vpnState.value.currentServer?.id
                    val newCurrent = updatedServers.find { it.id == selectedId } ?: updatedServers.first()
                    selectServer(newCurrent)
                    _infoMessage.value = if (errors > 0) {
                        "Обновлено ${updatedServers.size} серверов (частично)"
                    } else {
                        "Обновлено серверов: ${updatedServers.size}"
                    }
                } else {
                    _error.value = "Не удалось обновить подписки"
                }
            }
            saveData()
        }
    }

    fun removeSubscription(subscription: Subscription) {
        _subscriptions.update { current -> current.filter { it.id != subscription.id } }
        _servers.update { current -> current.filter { it !in subscription.servers } }
        if (_vpnState.value.currentServer != null && _vpnState.value.currentServer in subscription.servers) {
            _servers.value.firstOrNull()?.let { selectServer(it) }
        }
        saveData()
    }

    fun testPing(server: VPNServer) {
        viewModelScope.launch(Dispatchers.IO) {
            _servers.value = _servers.value.map {
                if (it.id == server.id) it.copy(ping = -2L) else it
            }
            val ping = VPNCore.testPing(server.host, server.port)
            _servers.value = _servers.value.map {
                if (it.id == server.id) it.copy(ping = ping) else it
            }
        }
    }

    fun testAllPings() {
        if (_servers.value.isEmpty()) {
            _error.value = "Нет серверов для проверки"
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            _isPinging.value = true
            val currentServers = _servers.value
            val updatedServers = currentServers.map { server ->
                val ping = VPNCore.testPing(server.host, server.port)
                server.copy(ping = ping)
            }
            withContext(Dispatchers.Main) {
                _servers.value = updatedServers
                _isPinging.value = false
                val ok = updatedServers.count { it.ping >= 0 }
                _infoMessage.value = "Пинг: $ok/${updatedServers.size} серверов отвечают"
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
                    _infoMessage.value = "Доступна версия ${release.tag_name}"
                } else {
                    _infoMessage.value = "У вас последняя версия (${BuildConfig.VERSION_NAME})"
                }
            } catch (e: Exception) {
                _error.value = "Не удалось проверить обновления: ${e.message}"
            } finally {
                _isCheckingUpdate.value = false
            }
        }
    }

    fun downloadUpdate() {
        val release = _updateRelease.value ?: return
        val apk = release.assets.firstOrNull { it.name.endsWith(".apk") } ?: return
        viewModelScope.launch {
            _infoMessage.value = "Скачивание обновления..."
            val ok = UpdateChecker.downloadAndInstall(context, apk)
            if (!ok) _error.value = "Не удалось скачать обновление"
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
        connectTimeoutJob?.cancel()
        try { context.unregisterReceiver(vpnStateReceiver) } catch (_: Exception) {}
        viewModelScope.cancel()
    }
}
