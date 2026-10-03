package com.quantumvpn.ui

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

internal fun serverPingText(ping: Int?, measured: Boolean): String = when {
    ping != null && ping > 0 -> "$ping мс"
    measured -> "Нет ответа"
    else -> "Проверка…"
}
