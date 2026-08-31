package com.quantumvpn.updates

/**
 * Tries the RosPanel update source first; if the panel has no release published (it throws
 * UpdateException) or is unreachable, falls back to the existing FTP/GitHub composite so the
 * app keeps working when the operator prefers GitHub/FTP distribution.
 */
class PanelFirstUpdateSource(
    private val panel: UpdateReleaseSource?,
    private val fallback: UpdateReleaseSource,
) : UpdateReleaseSource {
    override fun latest(channel: UpdateChannel): UpdateCandidate {
        if (panel == null) return fallback.latest(channel)
        return try {
            panel.latest(channel)
        } catch (_: UpdateException) {
            fallback.latest(channel)
        }
    }
}
