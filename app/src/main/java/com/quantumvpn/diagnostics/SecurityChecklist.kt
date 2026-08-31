package com.quantumvpn.diagnostics

import com.quantumvpn.ui.UiSettings
import com.quantumvpn.vpn.VpnConnectionState

data class ChecklistItem(
    val title: String,
    val ok: Boolean,
    val hint: String,
)

object SecurityChecklist {
    fun items(
        vpnState: VpnConnectionState,
        settings: UiSettings,
    ): List<ChecklistItem> = listOf(
        ChecklistItem(
            title = "VPN подключён",
            ok = vpnState is VpnConnectionState.Connected,
            hint = "Нажмите Подключить на главной.",
        ),
        ChecklistItem(
            title = "Kill switch",
            ok = settings.blockNonVpnTraffic,
            hint = "Настройки → Kill switch / блок трафика вне VPN.",
        ),
        ChecklistItem(
            title = "Блок localhost API",
            ok = settings.vpnHiding.blockLocalEndpoints,
            hint = "Настройки → Скрытие VPN.",
        ),
        ChecklistItem(
            title = "DNS-переопределение",
            ok = settings.dnsOverride.enabled,
            hint = "Настройки → DNS → включите override или пресет.",
        ),
        ChecklistItem(
            title = "Блокировка настроек",
            ok = settings.appLockEnabled,
            hint = "Настройки → Приватность → Блокировка настроек.",
        ),
        ChecklistItem(
            title = "Скрытие IP в UI",
            ok = settings.hideExitIp,
            hint = "Настройки → Приватность → Скрыть Exit IP.",
        ),
        ChecklistItem(
            title = "Защита скриншотов",
            ok = settings.flagSecure,
            hint = "Настройки → Приватность → Запрет скриншотов.",
        ),
    )

    fun summary(items: List<ChecklistItem>): String {
        val ok = items.count { it.ok }
        return "Чеклист безопасности: $ok/${items.size}"
    }
}
