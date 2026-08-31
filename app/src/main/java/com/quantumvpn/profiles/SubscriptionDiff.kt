package com.quantumvpn.profiles

import com.quantumvpn.config.ConfigAnalyzer

data class SubscriptionDiffResult(
    val profileId: String,
    val profileName: String,
    val added: List<String>,
    val removed: List<String>,
    val backupJson: String,
) {
    val hasChanges: Boolean get() = added.isNotEmpty() || removed.isNotEmpty()

    val summaryRu: String
        get() = buildString {
            append("Подписка «$profileName»: ")
            if (added.isNotEmpty()) append("+${added.size} ")
            if (removed.isNotEmpty()) append("−${removed.size}")
            if (!hasChanges) append("без изменений")
        }.trim()
}

object SubscriptionDiff {
    fun serverTags(json: String): Set<String> =
        ConfigAnalyzer.outboundDescriptions(json).keys
            .filter { tag ->
                tag != ConfigAnalyzer.MANAGED_SELECTOR_TAG &&
                    !tag.startsWith("dns-") &&
                    tag != "direct" &&
                    tag != "block" &&
                    tag != "dns-out"
            }
            .toSet()

    fun compute(
        profileId: String,
        profileName: String,
        oldJson: String,
        newJson: String,
    ): SubscriptionDiffResult {
        val oldTags = serverTags(oldJson)
        val newTags = serverTags(newJson)
        return SubscriptionDiffResult(
            profileId = profileId,
            profileName = profileName,
            added = (newTags - oldTags).sorted(),
            removed = (oldTags - newTags).sorted(),
            backupJson = oldJson,
        )
    }
}
