package com.quantumvpn.importer

/**
 * Parses Clash/V2Ray-style `subscription-userinfo` header:
 * `upload=…; download=…; total=…; expire=…`
 */
data class SubscriptionUserInfo(
    val uploadBytes: Long? = null,
    val downloadBytes: Long? = null,
    val totalBytes: Long? = null,
    val expireEpochSeconds: Long? = null,
) {
    val usedBytes: Long?
        get() {
            val up = uploadBytes ?: 0L
            val down = downloadBytes ?: 0L
            return if (uploadBytes != null || downloadBytes != null) up + down else null
        }

    val summaryRu: String
        get() = buildList {
            usedBytes?.let { used ->
                val total = totalBytes
                add(
                    if (total != null && total > 0) {
                        "Трафик ${formatBytes(used)} / ${formatBytes(total)}"
                    } else {
                        "Трафик ${formatBytes(used)}"
                    },
                )
            }
            expireEpochSeconds?.takeIf { it > 0 }?.let { exp ->
                val left = exp - (System.currentTimeMillis() / 1000)
                add(
                    when {
                        left <= 0 -> "Подписка истекла"
                        left < 86_400 -> "Истекает менее чем через сутки"
                        else -> "До ${(left / 86_400).toInt()} дн."
                    },
                )
            }
        }.joinToString(" · ")

    companion object {
        fun parse(raw: String?): SubscriptionUserInfo? {
            if (raw.isNullOrBlank()) return null
            var upload: Long? = null
            var download: Long? = null
            var total: Long? = null
            var expire: Long? = null
            raw.split(';', ',').forEach { part ->
                val kv = part.trim().split('=', limit = 2)
                if (kv.size != 2) return@forEach
                val key = kv[0].trim().lowercase()
                val value = kv[1].trim().toLongOrNull() ?: return@forEach
                when (key) {
                    "upload" -> upload = value
                    "download" -> download = value
                    "total" -> total = value
                    "expire" -> expire = value
                }
            }
            if (upload == null && download == null && total == null && expire == null) return null
            return SubscriptionUserInfo(upload, download, total, expire)
        }

        private fun formatBytes(value: Long): String = when {
            value < 1024 -> "$value B"
            value < 1024 * 1024 -> "%.0f KB".format(value / 1024.0)
            value < 1024L * 1024 * 1024 -> "%.1f MB".format(value / (1024.0 * 1024))
            else -> "%.2f GB".format(value / (1024.0 * 1024 * 1024))
        }
    }
}
