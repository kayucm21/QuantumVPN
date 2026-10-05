package com.quantumvpn.community

data class CommunityMessage(
    val id: Long,
    val sender: String,
    val body: String,
    val createdAtSeconds: Long,
    val hasDiagnostic: Boolean = false,
)

data class SupportThread(
    val id: Long,
    val subject: String,
    val state: String,
    val updatedAtSeconds: Long,
    val messages: List<CommunityMessage> = emptyList(),
)

data class InboxEntry(
    /** A server sequence or a stable local policy key; not an array position. */
    val key: String,
    val kind: String,
    val title: String,
    val body: String,
    val createdAtSeconds: Long,
    val serverId: Long = 0,
    val read: Boolean = false,
)

object InboxMerge {
    const val MAX_ENTRIES = 200

    fun merge(existing: List<InboxEntry>, incoming: List<InboxEntry>): List<InboxEntry> {
        val readKeys = existing.filter { it.read }.map { it.key }.toSet()
        return (existing + incoming).associateBy { it.key }.values
            .map { it.copy(read = it.read || it.key in readKeys) }
            .sortedWith(compareByDescending<InboxEntry> { it.createdAtSeconds }.thenByDescending { it.key })
            .take(MAX_ENTRIES)
    }
}

/** No host, URL, subscription, browsing history, or hardware ID is accepted. */
data class ClientQualityReport(
    val nodeKey: String,
    val protocol: String,
    val network: String,
    val connectMillis: Int,
    val pingMillis: Int,
    val disconnects: Int,
    val success: Boolean,
)

enum class DeliveryMilestone(val wireValue: String) {
    NotificationReceived("notification_received"),
    DownloadComplete("download_complete"),
    /** Launching Android's installer is not proof the person installed it. */
    InstallHandoff("install_handoff"),
    /** Report only the versionCode running in the newly started APK process. */
    AppStarted("app_started"),
}
