package com.quantumvpn.vpn

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

data class AppsUiState(
    val apps: List<InstalledApp> = emptyList(),
    val allowedPackages: Set<String> = emptySet(),
    val scopeMode: AppScopeMode = AppScopeMode.All,
    val initialized: Boolean = false,
    val catalogLoaded: Boolean = false,
    val loading: Boolean = false,
    val error: String? = null,
    val gameModeEnabled: Boolean = false,
    val detectedGames: List<DetectedGame> = emptyList(),
) {
    val needsAppSelection: Boolean
        get() = initialized && allowedPackages.isEmpty()

    val missingPackages: Set<String>
        get() = if (catalogLoaded) {
            allowedPackages - apps.asSequence().map(InstalledApp::packageName).toSet()
        } else {
            emptySet()
        }

    /** Выбранные пакеты игрового режима (для диагностики). */
    val gamePackages: Set<String>
        get() = detectedGames.flatMap(DetectedGame::selectedPackages).toSet()
}

/** Игра из каталога, найденная на устройстве, с отметками выбора. */
data class DetectedGame(
    val profile: GameProfile,
    val installedPackages: Set<String>,
    val selectedPackages: Set<String>,
)

class AppsViewModel(
    private val selectionStore: AppSelectionStore,
    private val appCatalog: AppCatalog,
    private val namedAppSetsStore: NamedAppSetsStore,
    private val gameModeStore: GameModeStore,
    private val vpnController: VpnController,
) : ViewModel() {
    private val apps = MutableStateFlow<List<InstalledApp>>(emptyList())
    private val catalogLoaded = MutableStateFlow(false)
    private val loading = MutableStateFlow(false)
    private val error = MutableStateFlow<String?>(null)

    init {
        refresh()
    }

    val namedSets = namedAppSetsStore.sets
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val state = combine(
        combine(
            apps,
            selectionStore.selection,
            catalogLoaded,
        ) { installedApps, selection, isCatalogLoaded ->
            Triple(installedApps, selection, isCatalogLoaded)
        },
        combine(
            loading,
            error,
            gameModeStore.snapshot,
        ) { isLoading, loadError, gameMode ->
            Triple(isLoading, loadError, gameMode)
        },
    ) { (installedApps, selection, isCatalogLoaded), (isLoading, loadError, gameMode) ->
        val detected = GameCatalog.detectInstalled(installedApps).map { (profile, present) ->
            DetectedGame(
                profile = profile,
                installedPackages = present,
                selectedPackages = present.intersect(gameMode.packages),
            )
        }
        AppsUiState(
            apps = installedApps,
            allowedPackages = selection.allowedPackages,
            scopeMode = selection.mode,
            initialized = selection.initialized,
            catalogLoaded = isCatalogLoaded,
            loading = isLoading,
            error = loadError,
            gameModeEnabled = gameMode.enabled,
            detectedGames = detected,
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.Eagerly,
        initialValue = AppsUiState(),
    )

    fun refresh() {
        if (loading.value) return
        loading.value = true
        error.value = null
        viewModelScope.launch {
            try {
                val installedApps = appCatalog.load()
                apps.value = installedApps
                catalogLoaded.value = true
                val enabledSuggestedApps = installedApps
                    .asSequence()
                    .filter(InstalledApp::enabled)
                    .filter { it.suggestion != null }
                    .map(InstalledApp::packageName)
                    .toSet()
                selectionStore.initializeIfNeeded(
                    suggestedPackages = enabledSuggestedApps,
                    newlySuggestedPackages = enabledSuggestedApps.intersect(
                        PopularAppSuggestions.packagesAddedInCurrentRevision,
                    ),
                    suggestionRevision = PopularAppSuggestions.MIGRATION_REVISION,
                )
            } catch (failure: CancellationException) {
                throw failure
            } catch (failure: Exception) {
                error.value = failure.message ?: "Не удалось прочитать список приложений."
            } finally {
                loading.value = false
            }
        }
    }

    fun setAllowed(packageName: String, allowed: Boolean) {
        viewModelScope.launch {
            selectionStore.setAllowed(packageName, allowed)
        }
    }

    fun setScopeMode(mode: AppScopeMode) {
        viewModelScope.launch { selectionStore.setMode(mode) }
    }

    fun removeMissingPackages() {
        val available = apps.value.asSequence().map(InstalledApp::packageName).toSet()
        viewModelScope.launch {
            selectionStore.replaceAllowlist(state.value.allowedPackages.intersect(available))
        }
    }

    fun applyPreset(preset: AppScopePreset) {
        viewModelScope.launch {
            val packages = AppScopePresets.packagesFor(preset, apps.value)
            selectionStore.setMode(AppScopeMode.Include)
            selectionStore.replaceAllowlist(packages)
        }
    }

    fun clearAllowlist() {
        viewModelScope.launch {
            selectionStore.replaceAllowlist(emptySet())
        }
    }

    fun selectAllVisible(packageNames: Collection<String>) {
        viewModelScope.launch {
            selectionStore.replaceAllowlist(state.value.allowedPackages + packageNames)
        }
    }

    fun invertSelection(visiblePackages: Collection<String>) {
        viewModelScope.launch {
            val current = state.value.allowedPackages.toMutableSet()
            visiblePackages.forEach { pkg ->
                if (pkg in current) current -= pkg else current += pkg
            }
            selectionStore.replaceAllowlist(current)
        }
    }

    fun saveNamedSet(name: String) {
        viewModelScope.launch {
            namedAppSetsStore.save(name, state.value.allowedPackages)
        }
    }

    fun loadNamedSet(set: NamedAppSet) {
        viewModelScope.launch {
            selectionStore.setMode(AppScopeMode.Include)
            selectionStore.replaceAllowlist(set.packages)
        }
    }

    fun deleteNamedSet(name: String) {
        viewModelScope.launch {
            namedAppSetsStore.delete(name)
        }
    }

    fun setGameModeEnabled(enabled: Boolean) {
        viewModelScope.launch {
            gameModeStore.setEnabled(enabled)
            vpnController.restartIfConnected("game-mode")
        }
    }

    fun setGamePackageEnabled(packageName: String, enabled: Boolean) {
        viewModelScope.launch {
            gameModeStore.setGameEnabled(packageName, enabled)
            vpnController.restartIfConnected("game-mode")
        }
    }

    /** Пакетное переключение (одна игра = один рестарт, а не по числу пакетов). */
    fun setGamePackagesEnabled(packageNames: Collection<String>, enabled: Boolean) {
        viewModelScope.launch {
            packageNames.forEach { gameModeStore.setGameEnabled(it, enabled) }
            vpnController.restartIfConnected("game-mode")
        }
    }

    /** Включить режим и выбрать все найденные на устройстве игры. */
    fun enableDetectedGames() {
        viewModelScope.launch {
            val detected = GameCatalog.detectInstalled(apps.value)
                .flatMap { (_, present) -> present }
                .toSet()
            gameModeStore.replaceGames(detected)
            gameModeStore.setEnabled(true)
            vpnController.restartIfConnected("game-mode")
        }
    }

    class Factory(
        private val selectionStore: AppSelectionStore,
        private val appCatalog: AppCatalog,
        private val namedAppSetsStore: NamedAppSetsStore,
        private val gameModeStore: GameModeStore,
        private val vpnController: VpnController,
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T =
            AppsViewModel(
                selectionStore,
                appCatalog,
                namedAppSetsStore,
                gameModeStore,
                vpnController,
            ) as T
    }
}
