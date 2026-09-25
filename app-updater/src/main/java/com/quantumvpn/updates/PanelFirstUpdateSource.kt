package com.quantumvpn.updates

/**
 * Uses the operator panel as the single update source.
 *
 * Older builds used to fall back to FTP/GitHub when the panel was unavailable. That made a
 * private VDS deployment look broken (and exposed a GitHub publication error) even though the
 * panel had a valid release. New builds must report the panel error directly instead.
 */
class PanelFirstUpdateSource(
    private val panel: UpdateReleaseSource?,
    private val fallback: UpdateReleaseSource? = null,
) : UpdateReleaseSource {
    override fun latest(channel: UpdateChannel): UpdateCandidate {
        return panel?.latest(channel)
            ?: fallback?.latest(channel)
            ?: throw UpdateException("Источник обновлений панели не настроен.")
    }
}
