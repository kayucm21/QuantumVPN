package com.quantumvpn.vpn

sealed interface VpnConnectionState {
    data object Stopped : VpnConnectionState
    data class Starting(
        val profileId: String,
        val message: String,
        val updaterRouting: Boolean = false,
    ) : VpnConnectionState
    data class Connected(
        val profileId: String,
        val profileName: String,
        val connectedAtEpochMillis: Long,
        val updaterRouting: Boolean = false,
    ) : VpnConnectionState
    data class Stopping(val profileId: String?) : VpnConnectionState
    data class Error(
        val message: String,
        val code: String = "",
        val technicalDetail: String? = null,
    ) : VpnConnectionState
}

data class RuntimeSelectorGroup(
    val tag: String,
    val type: String,
    val selected: String,
    val selectable: Boolean,
    val items: List<RuntimeOutboundItem>,
) {
    val outbounds: List<String>
        get() = items.map(RuntimeOutboundItem::tag)
}

data class RuntimeOutboundItem(
    val tag: String,
    val type: String,
    val endpoint: String?,
    val pingMillis: Int?,
    val pingMeasuredAtEpochSeconds: Long?,
)

data class TrafficSample(
    val uploadBytesPerSecond: Long,
    val downloadBytesPerSecond: Long,
)

data class VpnSessionStats(
    val profileId: String? = null,
    val connectedAtEpochMillis: Long? = null,
    val externalIp: String? = null,
    val exitCountry: String? = null,
    val exitCountryCode: String? = null,
    val exitFlagEmoji: String? = null,
    val pingMillis: Long? = null,
    val pingSamples: List<Long> = emptyList(),
    val pingAttempts: Int = 0,
    val pingSuccesses: Int = 0,
    val uploadTotalBytes: Long = 0,
    val downloadTotalBytes: Long = 0,
    val samples: List<TrafficSample> = emptyList(),
    val statusStreamActive: Boolean = false,
    val adBlockedPerMinute: Int = 0,
    val adBlockedSessionTotal: Long = 0L,
) {
    /** Mean absolute delta between consecutive probes, or null before two samples. */
    val jitterMillis: Long?
        get() = pingSamples.zipWithNext { a, b -> kotlin.math.abs(b - a) }
            .takeIf { it.isNotEmpty() }
            ?.average()
            ?.toLong()

    /** Loss over the current session's probe attempts. */
    val pingLossPercent: Int?
        get() = pingAttempts.takeIf { it > 0 }?.let {
            ((it - pingSuccesses.coerceIn(0, it)) * 100 / it).coerceIn(0, 100)
        }

    val exitLocation: ExitLocation?
        get() = when {
            !exitCountry.isNullOrBlank() -> ExitLocation(
                countryName = exitCountry,
                countryCode = exitCountryCode,
                flagEmoji = exitFlagEmoji,
            )
            else -> null
        }
}
