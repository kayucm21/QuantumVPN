package com.quantumvpn.vpn

import android.net.VpnService
import android.os.Build

data class VpnSystemPolicy(
    val statusAvailable: Boolean,
    val alwaysOn: Boolean,
    val lockdown: Boolean,
) {
    val blockingMessage: String?
        get() = when {
            lockdown ->
                "Android Lockdown VPN включён для QuantumVPN. " +
                    "Этот режим пока не поддерживается; отключите Always-on/Lockdown в настройках Android."
            alwaysOn ->
                "Android Always-on VPN включён для QuantumVPN. " +
                    "Автозапуск пока не поддерживается; отключите Always-on в настройках Android."
            else -> null
        }
}

internal object VpnSystemPolicyDetector {
    fun detect(service: VpnService): VpnSystemPolicy {
        VpnTestHooks.consumeVpnSystemPolicyOverride()?.let { return it }
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            VpnSystemPolicy(
                statusAvailable = true,
                alwaysOn = service.isAlwaysOn,
                lockdown = service.isLockdownEnabled,
            )
        } else {
            VpnSystemPolicy(statusAvailable = false, alwaysOn = false, lockdown = false)
        }
    }
}
