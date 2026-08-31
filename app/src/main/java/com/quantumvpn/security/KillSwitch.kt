package com.quantumvpn.security

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkRequest
import android.net.vcn.VcnManager
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import com.quantumvpn.networkbootstrap.networksCompat
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

/**
 * Kill Switch блокирует весь трафик при падении VPN соединения
 */
class KillSwitch(
    private val context: Context,
    private val dataStore: DataStore<Preferences>
) {
    companion object {
        private val KILL_SWITCH_ENABLED_KEY = booleanPreferencesKey("kill_switch_enabled")
    }

    private val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    fun isKillSwitchEnabled(): Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[KILL_SWITCH_ENABLED_KEY] ?: false
    }

    suspend fun setKillSwitchEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[KILL_SWITCH_ENABLED_KEY] = enabled
        }
    }

    /**
     * Проверяет, активно ли VPN подключение
     */
    fun isVpnActive(): Boolean {
        val activeNetwork = connectivityManager.activeNetwork ?: return false
        val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork) ?: return false
        return capabilities.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)
    }

    /**
     * Блокирует весь интернет-трафик при падении VPN
     */
    fun blockAllTraffic() {
        try {
            // Отключаем все сетевые интерфейсы кроме VPN
            val allNetworks = connectivityManager.networksCompat
            for (network in allNetworks) {
                val capabilities = connectivityManager.getNetworkCapabilities(network) ?: continue
                if (!capabilities.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) {
                    // Блокируем не-VPN сети
                    connectivityManager.bindProcessToNetwork(null)
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /**
     * Разблокирует трафик
     */
    fun unblockTraffic() {
        try {
            connectivityManager.bindProcessToNetwork(null)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}
