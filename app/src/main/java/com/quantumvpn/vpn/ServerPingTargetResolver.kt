package com.quantumvpn.vpn

import com.quantumvpn.config.ConfigAnalyzer
import com.quantumvpn.config.OutboundDescription
import com.quantumvpn.config.SelectorGroup

internal fun List<RuntimeSelectorGroup>.primaryGroup(): RuntimeSelectorGroup? {
    val candidates = filter { it.items.isNotEmpty() }
    if (candidates.isEmpty()) return null
    candidates.firstOrNull { group ->
        group.selectable &&
            group.tag.equals(ConfigAnalyzer.MANAGED_SELECTOR_TAG, ignoreCase = true)
    }?.let { return it }
    return candidates.firstOrNull { group ->
        group.selectable && group.items.any { it.tag == group.selected }
    } ?: candidates.first()
}

/** Keep a single server category on Home / Servers — the primary selectable group. */
internal fun List<RuntimeSelectorGroup>.forServerUi(): List<RuntimeSelectorGroup> =
    listOfNotNull(primaryGroup())

internal class ServerPingTargetResolver(
    private val descriptions: Map<String, OutboundDescription>,
    initialGroups: List<SelectorGroup>,
) {
    private val groupMembers = initialGroups.associate { it.tag to it.outbounds }
    private val initialSelections = initialGroups.associate { group ->
        group.tag to (group.default ?: group.outbounds.firstOrNull()).orEmpty()
    }

    fun selected(runtimeGroups: List<RuntimeSelectorGroup>): ServerPingTarget? {
        val selections = selections(runtimeGroups)
        val rootTag = runtimeGroups.primaryGroup()?.tag ?: initialSelections.keys.firstOrNull()
        val selectedTag = rootTag?.let(selections::get)
        if (selectedTag != null) {
            // A concrete outbound is selected. Resolve it to a server if it is
            // one; when it is a non-server (direct/urltest/…) there is no server
            // to ping, so do not fall back to an unrelated configured server.
            return resolveLeaf(selectedTag, selections)
        }
        return descriptions.values.singleOrNull { it.serverHost != null }?.toTarget()
    }

    fun group(
        groupTag: String,
        runtimeGroups: List<RuntimeSelectorGroup>,
    ): List<ServerPingTarget> {
        val selections = selections(runtimeGroups)
        val members = runtimeGroups.firstOrNull { it.tag == groupTag }
            ?.items
            ?.map(RuntimeOutboundItem::tag)
            ?.takeIf { it.isNotEmpty() }
            ?: groupMembers[groupTag].orEmpty()
        return members
            .flatMap { expandLeaves(it, selections, mutableSetOf()) }
            .distinctBy(ServerPingTarget::outboundTag)
    }

    private fun selections(runtimeGroups: List<RuntimeSelectorGroup>): Map<String, String> =
        initialSelections + runtimeGroups.associate { it.tag to it.selected }

    private fun resolveLeaf(
        startTag: String,
        selections: Map<String, String>,
    ): ServerPingTarget? =
        expandLeaves(startTag, selections, mutableSetOf()).firstOrNull()

    private fun expandLeaves(
        startTag: String,
        selections: Map<String, String>,
        visited: MutableSet<String>,
    ): List<ServerPingTarget> {
        if (!visited.add(startTag)) return emptyList()
        descriptions[startTag]?.toTarget()?.let { return listOf(it) }
        val nested = groupMembers[startTag]
        if (nested != null) {
            return nested.flatMap { member ->
                expandLeaves(member, selections, visited.toMutableSet())
            }
        }
        val next = selections[startTag] ?: return emptyList()
        return expandLeaves(next, selections, visited)
    }

    private fun OutboundDescription.toTarget(): ServerPingTarget? = serverHost
        ?.takeIf(String::isNotBlank)
        ?.takeUnless { com.quantumvpn.olcrtc.OlcrtcProtocol.isLoopbackHost(it) }
        ?.let { ServerPingTarget(outboundTag = tag, hostname = it) }
}
