package com.quantumvpn.vpn

/** In-memory, single-session traffic state. No timer, persistence or background polling. */
internal class SessionTrafficAccumulator(
    private val capacity: Int = 60,
) {
    private var generation: Long = Long.MIN_VALUE
    private val samples = ArrayDeque<TrafficSample>(capacity)
    private val pingSamples = ArrayDeque<Long>(capacity)

    var value: VpnSessionStats = VpnSessionStats()
        private set

    init {
        require(capacity > 0)
    }

    fun start(
        generation: Long,
        profileId: String,
        connectedAtEpochMillis: Long,
    ): VpnSessionStats {
        this.generation = generation
        samples.clear()
        pingSamples.clear()
        value = VpnSessionStats(
            profileId = profileId,
            connectedAtEpochMillis = connectedAtEpochMillis,
        )
        return value
    }

    fun stop(): VpnSessionStats {
        generation = Long.MIN_VALUE
        samples.clear()
        pingSamples.clear()
        value = VpnSessionStats()
        return value
    }

    fun setStatusStreamActive(generation: Long, active: Boolean): VpnSessionStats? {
        if (generation != this.generation) return null
        value = value.copy(statusStreamActive = active)
        return value
    }

    fun updateTraffic(
        generation: Long,
        uploadDelta: Long,
        downloadDelta: Long,
        uploadTotal: Long,
        downloadTotal: Long,
    ): VpnSessionStats? {
        if (generation != this.generation || !value.statusStreamActive) return null
        if (samples.size == capacity) samples.removeFirst()
        samples.addLast(
            TrafficSample(
                uploadBytesPerSecond = uploadDelta.coerceAtLeast(0),
                downloadBytesPerSecond = downloadDelta.coerceAtLeast(0),
            ),
        )
        value = value.copy(
            uploadTotalBytes = uploadTotal.coerceAtLeast(0),
            downloadTotalBytes = downloadTotal.coerceAtLeast(0),
            samples = samples.toList(),
        )
        return value
    }

    fun updateExternalIp(generation: Long, externalIp: String?): VpnSessionStats? {
        if (generation != this.generation) return null
        value = value.copy(externalIp = externalIp)
        return value
    }

    fun updateExitIdentity(
        generation: Long,
        externalIp: String?,
        location: ExitLocation?,
    ): VpnSessionStats? {
        if (generation != this.generation) return null
        value = value.copy(
            externalIp = externalIp,
            exitCountry = location?.countryName,
            exitCountryCode = location?.countryCode,
            exitFlagEmoji = location?.flagEmoji,
        )
        return value
    }

    fun updatePing(generation: Long, pingMillis: Long?): VpnSessionStats? {
        if (generation != this.generation) return null
        val sanitized = pingMillis?.coerceAtLeast(0)
        if (sanitized != null) {
            if (pingSamples.size == capacity) pingSamples.removeFirst()
            pingSamples.addLast(sanitized)
        }
        value = value.copy(
            pingMillis = sanitized,
            pingSamples = pingSamples.toList(),
        )
        return value
    }

    fun updateAdBlockStats(
        generation: Long,
        perMinute: Int,
        sessionTotal: Long,
    ): VpnSessionStats? {
        if (generation != this.generation) return null
        value = value.copy(
            adBlockedPerMinute = perMinute.coerceAtLeast(0),
            adBlockedSessionTotal = sessionTotal.coerceAtLeast(0),
        )
        return value
    }

    fun clearConnectionIdentity(generation: Long): VpnSessionStats? {
        if (generation != this.generation) return null
        value = value.copy(
            externalIp = null,
            exitCountry = null,
            exitCountryCode = null,
            exitFlagEmoji = null,
            pingMillis = null,
            pingSamples = emptyList(),
        )
        return value
    }
}
