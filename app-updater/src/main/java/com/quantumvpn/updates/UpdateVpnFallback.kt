package com.quantumvpn.updates

import android.content.Intent
import java.io.File

/**
 * App-owned bridge used after a retryable updater request has failed.
 * Prefer [withUnderlyingNetwork] (leave an active tunnel) before a full temporary VPN.
 */
interface UpdateVpnFallback {
    suspend fun connect(): UpdateVpnSession

    /** Bind the calling process to a non-VPN network for the duration of [block]. */
    suspend fun <T> withUnderlyingNetwork(block: () -> T): T = block()
}

/** Restores the VPN state that existed before the temporary updater route was enabled. */
fun interface UpdateVpnSession {
    suspend fun close()
}

/** Creates the app-owned, FileProvider-backed installer intent for a verified APK. */
fun interface UpdateInstallIntentFactory {
    fun create(file: File): Intent
}
