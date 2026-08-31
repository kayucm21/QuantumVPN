package com.quantumvpn.ui

import com.quantumvpn.hardening.BypassPreset
import com.quantumvpn.routing.RoutingPreset

/** One-tap connection experience modes on Home. */
enum class ConnectionExperienceMode {
    Normal,
    Video,
    Games,
    MaxBypass,
    Banks,
}

fun ConnectionExperienceMode.labelRu(): String = when (this) {
    ConnectionExperienceMode.Normal -> "Обычный"
    ConnectionExperienceMode.Video -> "Видео"
    ConnectionExperienceMode.Games -> "Игры"
    ConnectionExperienceMode.MaxBypass -> "Макс. обход"
    ConnectionExperienceMode.Banks -> "Банки"
}

fun ConnectionExperienceMode.routingPresetOrNull(): RoutingPreset? = when (this) {
    ConnectionExperienceMode.Normal -> null
    ConnectionExperienceMode.Video -> RoutingPreset.Streaming
    ConnectionExperienceMode.Games -> RoutingPreset.Gaming
    ConnectionExperienceMode.MaxBypass -> null
    ConnectionExperienceMode.Banks -> RoutingPreset.RussiaDirect
}

fun ConnectionExperienceMode.bypassPreset(): BypassPreset = when (this) {
    ConnectionExperienceMode.Normal -> BypassPreset.Standard
    ConnectionExperienceMode.Video -> BypassPreset.Tele2
    ConnectionExperienceMode.Games -> BypassPreset.Tele2
    ConnectionExperienceMode.MaxBypass -> BypassPreset.Aggressive
    ConnectionExperienceMode.Banks -> BypassPreset.Soft
}
