package com.quantumvpn.ui

import com.quantumvpn.updates.UpdateState

/** Pure display policy: never changes a VPN profile or Android system settings. */
internal fun auroraFontScale(systemScale: Float, largeText: Boolean): Float =
    systemScale.coerceAtLeast(1f) * if (largeText) 1.15f else 1f

internal fun backgroundSampleSize(width: Int, height: Int): Int {
    var sample = 1
    while (maxOf(width, height).toLong() / sample > 1440L) sample *= 2
    return sample
}

internal fun startupDownloadProgress(downloaded: Long, total: Long): Float? =
    if (total > 0L) (downloaded.coerceAtLeast(0L).toDouble() / total).toFloat().coerceIn(0f, 1f) else null

/** A stale UI-ready flag must never skip a check, download or installer handoff. */
internal fun startupFinishAllowed(ready: Boolean, update: UpdateState): Boolean = ready &&
    (update is UpdateState.UpToDate || update is UpdateState.Failure || update is UpdateState.Idle)

internal fun serverPingText(ping: Int?, measured: Boolean): String = when {
    ping != null && ping > 0 -> "$ping мс"
    measured -> "Нет ответа"
    else -> "Проверка…"
}

/** Upgrade the old bundled caption while preserving an operator's custom wording. */
internal fun quantum2Tagline(tagline: String): String =
    if (tagline.isBlank() || tagline == "HORIZON GLASS · 2026") "Больше свободы. Ближе к людям." else tagline
