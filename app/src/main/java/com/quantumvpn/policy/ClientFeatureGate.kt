package com.quantumvpn.policy

/**
 * Process-wide access to the latest panel feature flags (set from Application).
 * Missing / default = all allowed so offline clients keep working.
 */
object ClientFeatureGate {
    @Volatile
    var provider: () -> ClientFeatureFlags = { ClientFeatureFlags() }

    fun features(): ClientFeatureFlags = runCatching { provider() }.getOrDefault(ClientFeatureFlags())

    fun isAllowed(check: (ClientFeatureFlags) -> Boolean): Boolean =
        runCatching { check(features()) }.getOrDefault(true)
}
