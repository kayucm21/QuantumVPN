package com.quantumvpn.vpn

import android.content.Context

/**
 * Remembers that the user wants VPN to stay up across process death, task removal,
 * screen lock, and OEM background kills. Cleared only on explicit user/system stop.
 */
class VpnSessionDesireStore(context: Context) {
    private val prefs = context.applicationContext
        .getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    data class Desire(
        val wanted: Boolean,
        val profileId: String?,
        val updaterRouting: Boolean,
    )

    fun read(): Desire = Desire(
        wanted = prefs.getBoolean(KEY_WANTED, false),
        profileId = prefs.getString(KEY_PROFILE_ID, null)?.takeIf(String::isNotBlank),
        updaterRouting = prefs.getBoolean(KEY_UPDATER_ROUTING, false),
    )

    fun markWanted(profileId: String, updaterRouting: Boolean = false) {
        require(profileId.isNotBlank())
        prefs.edit()
            .putBoolean(KEY_WANTED, true)
            .putString(KEY_PROFILE_ID, profileId)
            .putBoolean(KEY_UPDATER_ROUTING, updaterRouting)
            .apply()
    }

    fun clear() {
        prefs.edit()
            .putBoolean(KEY_WANTED, false)
            .remove(KEY_PROFILE_ID)
            .putBoolean(KEY_UPDATER_ROUTING, false)
            .apply()
    }

    private companion object {
        const val PREFS = "vpn_session_desire"
        const val KEY_WANTED = "wanted"
        const val KEY_PROFILE_ID = "profile_id"
        const val KEY_UPDATER_ROUTING = "updater_routing"
    }
}
