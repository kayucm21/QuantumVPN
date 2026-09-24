package com.quantumvpn.policy

/** Remote kill-switches for QuantumVPN Android — keys match panel Android features. */
data class ClientFeatureFlags(
    val vpnConnect: Boolean = true,
    val killSwitch: Boolean = true,
    val splitTunnel: Boolean = true,
    val routingEditor: Boolean = true,
    val importJson: Boolean = true,
    val autoConnect: Boolean = true,
    val adblock: Boolean = true,
    val vpnSchedule: Boolean = true,
    val autoFailover: Boolean = true,
    val safeMode: Boolean = true,
    val stealthMode: Boolean = true,
    val carrierBypass: Boolean = true,
)

/** Small, signed-by-transport branding payload controlled by the operator panel.
 * It deliberately contains presentation-only values; no credentials or tracking
 * settings are accepted from the remote config.
 */
data class ClientBranding(
    val name: String = "QuantumVPN",
    val tagline: String = "HORIZON GLASS · 2026",
    val accentHex: String = "#3DE7FF",
)

data class ClientPolicy(
    val platform: String = "android",
    val announce: String = "",
    val announceUntil: Long = 0,
    val minVersion: String = "",
    val latestVersion: String = "",
    val versionCode: Long = 0,
    val forceUpdate: Boolean = false,
    val updateUrl: String = "",
    val sha256: String = "",
    val note: String = "",
    val features: ClientFeatureFlags = ClientFeatureFlags(),
    val maintenance: Boolean = false,
    val maintenanceMessage: String = "",
    val bannedSerials: List<String> = emptyList(),
    val bannedIps: List<String> = emptyList(),
    val banned: Boolean = false,
    val adsListUrl: String = "",
    val adblockLevel: String = "",
    val branding: ClientBranding = ClientBranding(),
) {
    fun activeAnnounce(nowEpochSec: Long = System.currentTimeMillis() / 1000): String {
        if (announce.isBlank()) return ""
        if (announceUntil > 0 && nowEpochSec > announceUntil) return ""
        return announce
    }

    fun blockReason(
        currentVersionCode: Long,
        deviceSerial: String = "",
        publicIp: String = "",
    ): String? {
        if (banned || (deviceSerial.isNotBlank() && bannedSerials.any { it.equals(deviceSerial, ignoreCase = true) })) {
            return maintenanceMessage.ifBlank { "Устройство заблокировано оператором." }
        }
        if (publicIp.isNotBlank() && bannedIps.any { it == publicIp }) {
            return "IP заблокирован оператором."
        }
        if (maintenance) {
            return maintenanceMessage.ifBlank { "Технические работы. VPN временно недоступен." }
        }
        if (!features.vpnConnect) {
            return "Подключение отключено оператором."
        }
        if (forceUpdate && versionCode > 0 && currentVersionCode < versionCode) {
            val extra = note.trim()
            return if (extra.isEmpty()) {
                "Требуется обновление до $latestVersion"
            } else {
                "Требуется обновление до $latestVersion. $extra"
            }
        }
        return null
    }
}
