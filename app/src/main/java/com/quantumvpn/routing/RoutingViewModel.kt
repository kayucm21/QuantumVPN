package com.quantumvpn.routing

import com.quantumvpn.diagnostics.SecretRedactor
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.quantumvpn.profiles.ProfileStore
import com.quantumvpn.ui.UiSettingsStore
import com.quantumvpn.vpn.VpnController
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class RoutingUiState(
    val activeProfileId: String? = null,
    val activeProfileName: String? = null,
    val inspection: RoutingInspection? = null,
    val happCatalog: HappRoutingCatalog = HappRoutingCatalog(),
    val ruleSetVersion: Int? = null,
    val loading: Boolean = false,
    val message: String? = null,
    val managedDiff: String? = null,
    val undoMessage: String? = null,
) {
    val happRoutingAvailable: Boolean
        get() = happCatalog.profiles.isNotEmpty()

    val homeRoutingLabel: String
        get() = when {
            happRoutingAvailable -> happCatalog.displayName
            inspection != null -> inspection.preset.title
            else -> "Загрузка…"
        }
}

class RoutingViewModel(
    private val profileStore: ProfileStore,
    private val settingsStore: UiSettingsStore,
    private val ruleSetAssets: RuleSetAssetManager,
    private val vpnController: VpnController,
    private val happRoutingStore: HappRoutingProfileStore,
) : ViewModel() {
    private var pendingRoutingUndoJson: String? = null
    private val mutableState = MutableStateFlow(RoutingUiState())
    val state: StateFlow<RoutingUiState> = mutableState.asStateFlow()

    init {
        viewModelScope.launch {
            profileStore.initialize()
            runCatching { refreshRuleSetsInternal() }
            combine(profileStore.profiles, settingsStore.settings) { profiles, settings ->
                profiles.firstOrNull { it.id == settings.activeProfileId }
            }
                .map { it?.id to it?.name }
                .distinctUntilChanged()
                .collect { (id, name) ->
                    mutableState.update { it.copy(activeProfileId = id, activeProfileName = name) }
                    refresh()
                }
        }
    }

    fun refreshRuleSets() {
        viewModelScope.launch {
            mutableState.update { it.copy(loading = true, message = null) }
            try {
                val installed = refreshRuleSetsInternal()
                val id = mutableState.value.activeProfileId
                if (id != null) {
                    val profile = profileStore.read(id)
                    if (RoutingConfigEditor.usesManagedLocalRuleSets(profile.json)) {
                        val rebound = RoutingConfigEditor.rebindManagedRuleSetPaths(
                            profile.json,
                            installed,
                        )
                        profileStore.update(id, rebound)
                        refresh()
                    }
                }
                vpnController.restartIfConnected("Обновление rule-set маршрутизации")
                mutableState.update {
                    it.copy(
                        loading = false,
                        message = "Списки маршрутизации обновлены (v${installed.version}).",
                    )
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                mutableState.update {
                    it.copy(
                        loading = false,
                        message = error.message?.let(SecretRedactor::redactInline)?.take(320)
                            ?: "Не удалось обновить списки маршрутизации.",
                    )
                }
            }
        }
    }

    fun refreshRuleSetsFromRemote(manifestUrl: String) {
        viewModelScope.launch {
            mutableState.update { it.copy(loading = true, message = null) }
            try {
                val installed = withContext(Dispatchers.IO) {
                    ruleSetAssets.refreshFromRemote(manifestUrl)
                }
                mutableState.update { it.copy(ruleSetVersion = installed.version) }
                val id = mutableState.value.activeProfileId
                if (id != null) {
                    val profile = profileStore.read(id)
                    if (RoutingConfigEditor.usesManagedLocalRuleSets(profile.json)) {
                        val rebound = RoutingConfigEditor.rebindManagedRuleSetPaths(
                            profile.json,
                            installed,
                        )
                        profileStore.update(id, rebound)
                        refresh()
                    }
                }
                vpnController.restartIfConnected("Remote rule-set update")
                mutableState.update {
                    it.copy(
                        loading = false,
                        message = "Remote rule-set v${installed.version} установлен.",
                    )
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                mutableState.update {
                    it.copy(
                        loading = false,
                        message = error.message?.let(SecretRedactor::redactInline)?.take(320)
                            ?: "Remote rule-set не обновлён.",
                    )
                }
            }
        }
    }

    private suspend fun refreshRuleSetsInternal(): InstalledRuleSets {
        val installed = withContext(Dispatchers.IO) { ruleSetAssets.ensureInstalled() }
        mutableState.update { it.copy(ruleSetVersion = installed.version) }
        return installed
    }

    fun refresh() {
        val id = mutableState.value.activeProfileId ?: run {
            mutableState.update {
                it.copy(
                    inspection = null,
                    happCatalog = HappRoutingCatalog(),
                    loading = false,
                )
            }
            return
        }
        viewModelScope.launch {
            mutableState.update { it.copy(loading = true) }
            try {
                val profile = profileStore.read(id)
                val catalog = happRoutingStore.get(id)
                val inspection = withContext(Dispatchers.Default) {
                    RoutingConfigEditor.inspect(profile.json)
                }
                mutableState.update {
                    it.copy(
                        inspection = inspection,
                        happCatalog = catalog,
                        loading = false,
                    )
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                mutableState.update {
                    it.copy(
                        loading = false,
                        message = error.message?.let(SecretRedactor::redactInline)?.take(320)
                            ?: "Не удалось прочитать маршруты.",
                    )
                }
            }
        }
    }

    fun setHappRoutingEnabled(enabled: Boolean) {
        val id = mutableState.value.activeProfileId ?: return
        viewModelScope.launch {
            mutableState.update { it.copy(loading = true, message = null) }
            try {
                val catalog = happRoutingStore.setEnabled(id, enabled)
                applyCatalog(id, catalog, "Маршрутизация ${if (enabled) "включена" else "выключена"}.")
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                fail(error, "Не удалось переключить маршрутизацию.")
            }
        }
    }

    fun selectHappRoutingProfile(name: String) {
        val id = mutableState.value.activeProfileId ?: return
        viewModelScope.launch {
            mutableState.update { it.copy(loading = true, message = null) }
            try {
                val catalog = happRoutingStore.setActive(id, name)
                applyCatalog(id, catalog, "Профиль маршрутизации: $name")
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                fail(error, "Не удалось выбрать профиль маршрутизации.")
            }
        }
    }

    fun applyPreset(preset: RoutingPreset) = edit { inspection ->
        preset to inspection.rules
    }

    fun saveRule(index: Int?, rule: ManagedRoutingRule) = edit { inspection ->
        rule.values.forEach { value ->
            HomographGuard.warning(value)?.let { warn ->
                throw IllegalArgumentException(warn)
            }
        }
        val rules = inspection.rules.toMutableList()
        if (index == null) rules += rule
        else {
            require(index in rules.indices) { "Правило больше не существует." }
            rules[index] = rule
        }
        inspection.preset to rules
    }

    fun deleteRule(index: Int) {
        val id = mutableState.value.activeProfileId ?: return
        if (mutableState.value.loading) return
        viewModelScope.launch {
            val backupJson = profileStore.read(id).json
            edit { inspection ->
                require(index in inspection.rules.indices) { "Правило больше не существует." }
                inspection.preset to inspection.rules.filterIndexed { position, _ -> position != index }
            }
            pendingRoutingUndoJson = backupJson
            mutableState.update { it.copy(undoMessage = "Правило удалено") }
        }
    }

    fun undoRoutingChange() {
        val id = mutableState.value.activeProfileId ?: return
        val backup = pendingRoutingUndoJson ?: return
        viewModelScope.launch {
            profileStore.update(id, backup)
            pendingRoutingUndoJson = null
            refresh()
            mutableState.update { it.copy(undoMessage = null, message = "Маршрутизация восстановлена.") }
            vpnController.restartIfConnected("Откат маршрутизации")
        }
    }

    fun consumeRoutingUndo() {
        pendingRoutingUndoJson = null
        mutableState.update { it.copy(undoMessage = null) }
    }

    fun addDomainRuleFromShare(text: String) {
        val domain = ShareRouting.extractDomain(text) ?: run {
            mutableState.update {
                it.copy(message = "Не удалось извлечь домен из «${text.take(48)}».")
            }
            return
        }
        HomographGuard.warning(domain)?.let { warn ->
            mutableState.update { it.copy(message = warn) }
            return
        }
        val rule = ManagedRoutingRule(
            matchType = RoutingMatchType.DomainSuffix,
            values = listOf(domain),
            action = RoutingRuleAction.Proxy,
        )
        saveRule(index = null, rule = rule)
        mutableState.update {
            it.copy(message = "Добавлено правило: $domain → VPN.")
        }
    }

    fun consumeMessage() {
        mutableState.update { it.copy(message = null) }
    }

    private suspend fun applyCatalog(
        profileId: String,
        catalog: HappRoutingCatalog,
        message: String,
    ) {
        val installed = ruleSetAssets.ensureInstalled()
        val profile = profileStore.read(profileId)
        val json = withContext(Dispatchers.Default) {
            HappRoutingCompiler.applyToProfileJson(profile.json, catalog, installed)
        }
        profileStore.update(profileId, json)
        val inspection = withContext(Dispatchers.Default) {
            RoutingConfigEditor.inspect(json)
        }
        mutableState.update {
            it.copy(
                happCatalog = catalog,
                inspection = inspection,
                loading = false,
                message = message,
            )
        }
        vpnController.restartIfConnected("Изменение маршрутизации Happ")
    }

    private fun fail(error: Exception, fallback: String) {
        mutableState.update {
            it.copy(
                loading = false,
                message = error.message?.let(SecretRedactor::redactInline)?.take(320) ?: fallback,
            )
        }
    }

    private fun edit(
        transform: (RoutingInspection) -> Pair<RoutingPreset, List<ManagedRoutingRule>>,
    ) {
        val id = mutableState.value.activeProfileId ?: return
        if (mutableState.value.loading) return
        viewModelScope.launch {
            mutableState.update { it.copy(loading = true, message = null) }
            try {
                val installed = ruleSetAssets.ensureInstalled()
                val profile = profileStore.read(id)
                val current = RoutingConfigEditor.inspect(profile.json)
                val (preset, rules) = transform(current)
                val result = withContext(Dispatchers.Default) {
                    RoutingConfigEditor.apply(profile.json, preset, rules, installed)
                }
                profileStore.update(id, result.json)
                mutableState.update {
                    it.copy(
                        inspection = result.inspection,
                        loading = false,
                        managedDiff = result.diff,
                        message = "Маршрутизация сохранена в JSON профиля.",
                    )
                }
                vpnController.restartIfConnected("Изменение маршрутизации")
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                fail(error, "Не удалось сохранить маршрутизацию.")
            }
        }
    }

    class Factory(
        private val profileStore: ProfileStore,
        private val settingsStore: UiSettingsStore,
        private val ruleSetAssets: RuleSetAssetManager,
        private val vpnController: VpnController,
        private val happRoutingStore: HappRoutingProfileStore,
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            require(modelClass.isAssignableFrom(RoutingViewModel::class.java))
            return RoutingViewModel(
                profileStore,
                settingsStore,
                ruleSetAssets,
                vpnController,
                happRoutingStore,
            ) as T
        }
    }
}
