package com.quantumvpn.importer

import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.quantumvpn.config.JsonConfig
import com.quantumvpn.profiles.ManagedProfileFactory
import com.quantumvpn.profiles.ManagedServer
import com.quantumvpn.profiles.ProfileSource
import com.quantumvpn.profiles.ProtocolOutboundBuilders
import com.quantumvpn.profiles.TlsSettings
import com.quantumvpn.profiles.TransportSettings
import com.quantumvpn.wireguardimport.WireGuardConfigParser
import com.quantumvpn.wireguardimport.WireGuardImportException
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Base64
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull

sealed interface ImportCandidate {
    val suggestedName: String
    val source: ProfileSource

    data class RawJson(
        val json: String,
        override val suggestedName: String,
        override val source: ProfileSource,
    ) : ImportCandidate

    data class Managed(
        val servers: List<ManagedServer>,
        override val suggestedName: String,
        override val source: ProfileSource,
    ) : ImportCandidate {
        fun buildJson(): String = if (servers.size == 1) {
            ManagedProfileFactory.single(servers.single())
        } else {
            ManagedProfileFactory.subscription(servers)
        }
    }

    data class WireGuard(
        val json: String,
        val protocolName: String,
        val endpointLabel: String?,
        override val suggestedName: String,
        override val source: ProfileSource,
    ) : ImportCandidate
}

data class ImportParseResult(
    val candidate: ImportCandidate,
    val routing: com.quantumvpn.routing.HappRoutingImport = com.quantumvpn.routing.HappRoutingImport.None,
)

class ImportException(
    message: String,
    val httpStatus: Int? = null,
    cause: Throwable? = null,
) : Exception(message, cause)

object ImportParser {
    fun parse(
        input: String,
        source: ProfileSource,
        suggestedName: String = "Импортированный профиль",
        routingHeader: String? = null,
    ): ImportParseResult {
        val extracted = com.quantumvpn.routing.HappRoutingParser.extractFromBody(input)
        val headerImport = com.quantumvpn.routing.HappRoutingParser.parseHeader(routingHeader)
        val routing = com.quantumvpn.routing.HappRoutingParser.merge(extracted.import, headerImport)
        val text = extracted.bodyWithoutRouting.removePrefix("\uFEFF").trim()
        if (text.isEmpty()) {
            if (routing !is com.quantumvpn.routing.HappRoutingImport.None) {
                throw ImportException(
                    "В ответе есть профили маршрутизации Happ, но нет серверов подписки.",
                )
            }
            throw ImportException("Источник импорта пуст.")
        }
        val candidate = parseBody(text, source, suggestedName)
        return ImportParseResult(candidate = candidate, routing = routing)
    }

    /** True when the pasted value is local config/share-link content, not an HTTP(S) subscription URL. */
    fun looksLikeInlineImport(raw: String): Boolean {
        val text = raw.trim()
        if (text.isEmpty()) return false
        if (looksLikeSubscriptionUrl(text)) return false
        if (text.startsWith('{') || WireGuardConfigParser.looksLikeConfig(text)) return true
        if (extractSupportedLinks(text).isNotEmpty()) return true
        val decoded = runCatching { decodeBase64(text.filterNot(Char::isWhitespace)) }.getOrNull()
        return decoded != null && extractSupportedLinks(decoded).isNotEmpty()
    }

    /** Single-line HTTP(S) subscription URL copied into clipboard / QR / URL field. */
    fun looksLikeSubscriptionUrl(raw: String): Boolean {
        val text = extractHttpUrl(raw) ?: return false
        return !looksLikeInlineImportIgnoringUrl(text)
    }

    private fun looksLikeInlineImportIgnoringUrl(text: String): Boolean {
        if (text.startsWith('{') || WireGuardConfigParser.looksLikeConfig(text)) return true
        if (extractSupportedLinks(text).isNotEmpty()) return true
        val decoded = runCatching { decodeBase64(text.filterNot(Char::isWhitespace)) }.getOrNull()
        return decoded != null && extractSupportedLinks(decoded).isNotEmpty()
    }

    fun extractHttpUrl(raw: String): String? {
        val text = raw.trim().trim('"', '\'', '«', '»', '`')
        if (text.isEmpty()) return null
        val singleLine = text.lineSequence().map(String::trim).filter { it.isNotEmpty() }.toList()
        if (singleLine.size == 1) {
            val line = singleLine.single()
            if (line.startsWith("http://", true) || line.startsWith("https://", true)) {
                return line.trimEnd(',', ';', '.', ')', ']')
            }
        }
        val match = HTTP_URL.find(text) ?: return null
        // Prefer whole-clipboard URL imports when the only meaningful content is one URL.
        val compact = text.replace(Regex("""\s+"""), " ").trim()
        val candidate = match.value.trimEnd(',', ';', '.', ')', ']')
        if (compact.equals(candidate, ignoreCase = true) ||
            compact.startsWith("http", ignoreCase = true) && compact.length <= candidate.length + 8
        ) {
            return candidate
        }
        // "Подписка: https://..." style clipboard payloads.
        if (singleLine.size <= 2 && extractSupportedLinks(text).isEmpty()) {
            return candidate
        }
        return null
    }

    private fun parseBody(
        text: String,
        source: ProfileSource,
        suggestedName: String,
    ): ImportCandidate {
        if (looksLikeClashYaml(text)) {
            val servers = ClashYamlImporter.parse(text)
            val unique = com.quantumvpn.profiles.ServerDeduper.dedupe(servers)
            return ImportCandidate.Managed(
                servers = unique,
                suggestedName = if (unique.size == 1) unique.single().displayName else suggestedName,
                source = ProfileSource.File,
            )
        }
        if (text.startsWith('{')) {
            try {
                JsonConfig.parse(text)
            } catch (error: Exception) {
                throw ImportException("Файл не содержит корректный JSON.", cause = error)
            }
            return ImportCandidate.RawJson(
                json = JsonConfig.format(text),
                suggestedName = suggestedName,
                source = source,
            )
        }
        if (WireGuardConfigParser.looksLikeConfig(text)) {
            val wireGuard = try {
                WireGuardConfigParser.parse(text)
            } catch (error: WireGuardImportException) {
                throw ImportException(error.message ?: "Не удалось преобразовать WireGuard .conf.", cause = error)
            }
            return ImportCandidate.WireGuard(
                json = wireGuard.json,
                protocolName = wireGuard.protocolName,
                endpointLabel = wireGuard.endpointLabel,
                suggestedName = suggestedName,
                source = source,
            )
        }

        val linkText = decodeSubscriptionIfNeeded(text)
        val links = extractSupportedLinks(linkText)
        if (links.isEmpty()) throw ImportException(SUPPORTED_MESSAGE)
        val servers = links.mapIndexedNotNull { index, link ->
            runCatching { ShareLinkParser.parse(link, index) }.getOrNull()
        }
        if (servers.isEmpty()) {
            throw ImportException("Не удалось разобрать ни одной поддерживаемой ссылки.")
        }
        val unique = com.quantumvpn.profiles.ServerDeduper.dedupe(servers)
        return ImportCandidate.Managed(
            servers = unique,
            suggestedName = if (unique.size == 1) unique.single().displayName else suggestedName,
            source = if (unique.size == 1) {
                when (source) {
                    ProfileSource.Qr -> ProfileSource.Qr
                    ProfileSource.Url -> ProfileSource.Url
                    else -> ProfileSource.Link
                }
            } else {
                ProfileSource.Subscription
            },
        )
    }

    private fun looksLikeClashYaml(text: String): Boolean {
        val head = text.lineSequence().take(40).joinToString("\n")
        if (head.contains("proxies:") && (head.contains("proxy-groups:") || head.contains("rules:"))) {
            return true
        }
        return head.contains("mixed-port:") && head.contains("proxies:")
    }

    private fun decodeSubscriptionIfNeeded(text: String): String {
        if (extractSupportedLinks(text).isNotEmpty()) {
            return text
        }
        val decoded = runCatching { decodeBase64(text.filterNot(Char::isWhitespace)) }.getOrNull()
            ?: return text
        return if (extractSupportedLinks(decoded).isNotEmpty()) decoded else text
    }

    /** Keep supported share links; skip comments, junk and unknown schemes. */
    private fun extractSupportedLinks(text: String): List<String> {
        val fromLines = text.lineSequence()
            .map(String::trim)
            .filter { it.isNotEmpty() && !it.startsWith('#') }
            .map { line ->
                SUPPORTED_SCHEMES
                    .firstOrNull { scheme -> line.startsWith(scheme, ignoreCase = true) }
                    ?.let { scheme ->
                        val start = line.indexOf(scheme, ignoreCase = true)
                        line.substring(start).trimEnd(',', ';', ')', ']', '"', '\'')
                    }
                    ?: EMBEDDED_LINK.find(line)?.value?.trimEnd(',', ';', ')', ']', '"', '\'')
            }
            .filterNotNull()
            .filter { link -> SUPPORTED_SCHEMES.any { link.startsWith(it, ignoreCase = true) } }
            .toList()
        if (fromLines.isNotEmpty()) return fromLines.distinct()

        return EMBEDDED_LINK.findAll(text)
            .map { it.value.trimEnd(',', ';', ')', ']', '"', '\'') }
            .filter { link -> SUPPORTED_SCHEMES.any { link.startsWith(it, ignoreCase = true) } }
            .distinct()
            .toList()
    }

    private const val SUPPORTED_MESSAGE =
        "Поддерживаются JSON, WireGuard/AWG .conf, Clash YAML (только proxies), " +
            "VLESS, VMess, Trojan, Shadowsocks, Hysteria, Hysteria2 и TUIC."
    private val SUPPORTED_SCHEMES = listOf(
        "vless://",
        "vmess://",
        "trojan://",
        "ss://",
        "hysteria://",
        "hysteria2://",
        "hy2://",
        "tuic://",
    )
    private val EMBEDDED_LINK = Regex(
        """(?i)\b(?:vless|vmess|trojan|ss|hysteria2?|hy2|tuic)://[^\s<>"']+""",
    )
    private val HTTP_URL = Regex(
        """(?i)https?://[^\s<>"'）】\]]+""",
    )
}

object ShareLinkParser {
    fun parse(link: String, index: Int = 0): ManagedServer = try {
        when {
            link.startsWith("vless://", ignoreCase = true) -> parseVless(link, index)
            link.startsWith("vmess://", ignoreCase = true) -> parseVmess(link, index)
            link.startsWith("trojan://", ignoreCase = true) -> parseTrojan(link, index)
            link.startsWith("ss://", ignoreCase = true) -> parseShadowsocks(link, index)
            link.startsWith("hysteria://", ignoreCase = true) -> parseHysteria(link, index)
            link.startsWith("hysteria2://", ignoreCase = true) ||
                link.startsWith("hy2://", ignoreCase = true) -> parseHysteria2(link, index)
            link.startsWith("tuic://", ignoreCase = true) -> parseTuic(link, index)
            else -> throw ImportException("Неподдерживаемый тип ссылки.")
        }
    } catch (error: ImportException) {
        throw error
    } catch (error: Exception) {
        throw ImportException("Не удалось разобрать ссылку №${index + 1}.", cause = error)
    }

    private fun parseVless(link: String, index: Int): ManagedServer {
        val uri = URI(link)
        val host = requireHost(uri)
        val query = query(uri)
        val name = displayName(uri, "VLESS ${index + 1}")
        val uuid = decode(uri.rawUserInfo).takeIf(String::isNotBlank)
            ?: throw ImportException("В VLESS отсутствует UUID.")
        return ProtocolOutboundBuilders.vless(
            displayName = name,
            server = host,
            serverPort = requirePort(uri),
            uuid = uuid,
            flow = query["flow"],
            tls = tls(query, host),
            transport = transport(query, allowXhttp = true),
        )
    }

    private fun parseTrojan(link: String, index: Int): ManagedServer {
        val uri = URI(link)
        val host = requireHost(uri)
        val query = query(uri)
        val password = decode(uri.rawUserInfo).takeIf(String::isNotBlank)
            ?: throw ImportException("В Trojan отсутствует пароль.")
        return ProtocolOutboundBuilders.trojan(
            displayName = displayName(uri, "Trojan ${index + 1}"),
            server = host,
            serverPort = requirePort(uri),
            password = password,
            tls = tls(query, host, defaultEnabled = true),
            transport = transport(query),
        )
    }

    private fun parseVmess(link: String, index: Int): ManagedServer {
        val encoded = link.substringAfter("vmess://").substringBefore('#').trim()
        val data = JsonConfig.parse(decodeBase64(encoded)) as? JsonObject
            ?: throw ImportException("VMess payload должен быть JSON-объектом.")
        val host = data.text("add") ?: throw ImportException("В VMess отсутствует сервер.")
        val port = data.number("port") ?: throw ImportException("В VMess отсутствует порт.")
        val uuid = data.text("id") ?: throw ImportException("В VMess отсутствует UUID.")
        val network = data.text("net").orEmpty()
        val transport = when (network) {
            "", "tcp" -> null
            "ws", "http", "httpupgrade" -> TransportSettings(
                type = network,
                path = data.text("path"),
                host = data.text("host"),
            )
            "grpc" -> TransportSettings(type = network, serviceName = data.text("path"))
            else -> throw ImportException("VMess transport '$network' пока не поддерживается.")
        }
        val tlsEnabled = data.text("tls")?.lowercase() in setOf("tls", "reality")
        return ProtocolOutboundBuilders.vmess(
            displayName = data.text("ps") ?: "VMess ${index + 1}",
            server = host,
            serverPort = port,
            uuid = uuid,
            security = data.text("scy") ?: "auto",
            alterId = data.number("aid") ?: 0,
            tls = TlsSettings(
                enabled = tlsEnabled,
                serverName = data.text("sni") ?: host,
                insecure = data.text("allowInsecure") == "1",
                utlsFingerprint = data.text("fp"),
            ),
            transport = transport,
        )
    }

    private fun parseShadowsocks(link: String, index: Int): ManagedServer {
        val body = link.substringAfter("ss://")
        val fragment = body.substringAfter('#', "")
        val beforeFragment = body.substringBefore('#')
        val rawQuery = beforeFragment.substringAfter('?', "")
        if (rawQuery.split('&').any { decode(it.substringBefore('=')).equals("plugin", true) }) {
            throw ImportException("Shadowsocks plugin в URI пока не поддерживается.")
        }
        val withoutFragment = beforeFragment.substringBefore('?')
        val expanded = if ('@' in withoutFragment) withoutFragment else decodeBase64(withoutFragment)
        val credentialPart = expanded.substringBeforeLast('@')
        val serverPart = expanded.substringAfterLast('@', "")
        if (serverPart.isBlank()) throw ImportException("В Shadowsocks отсутствует сервер.")
        val credentials = decodeCredentials(credentialPart)
        val method = credentials.substringBefore(':')
        val password = credentials.substringAfter(':', "")
        if (method.isBlank() || password.isBlank()) {
            throw ImportException("В Shadowsocks отсутствуют method или password.")
        }
        val serverUri = URI("ss://placeholder@$serverPart")
        return ProtocolOutboundBuilders.shadowsocks(
            displayName = decode(fragment).ifBlank { "Shadowsocks ${index + 1}" },
            server = requireHost(serverUri),
            serverPort = requirePort(serverUri),
            method = method,
            password = password,
        )
    }

    private fun parseHysteria(link: String, index: Int): ManagedServer {
        val uri = URI(link)
        val host = requireHost(uri)
        val query = query(uri)
        val authStr = decode(uri.rawUserInfo).takeIf(String::isNotBlank)
            ?: query["auth"]?.takeIf(String::isNotBlank)
            ?: throw ImportException("В Hysteria отсутствует пароль.")
        return ProtocolOutboundBuilders.hysteria(
            displayName = displayName(uri, "Hysteria ${index + 1}"),
            server = host,
            serverPort = requirePort(uri),
            authStr = authStr,
            obfs = query["obfs"] ?: query["protocol"],
            upMbps = query["upmbps"]?.toIntOrNull() ?: query["up"]?.toIntOrNull(),
            downMbps = query["downmbps"]?.toIntOrNull() ?: query["down"]?.toIntOrNull(),
            tls = TlsSettings(
                enabled = true,
                serverName = query["peer"] ?: query["sni"] ?: host,
                insecure = query.boolean("insecure") || query.boolean("allowInsecure"),
            ),
        )
    }

    private fun parseHysteria2(link: String, index: Int): ManagedServer {
        val normalized = if (link.startsWith("hy2://", true)) {
            "hysteria2://" + link.substringAfter("://")
        } else {
            link
        }
        val uri = URI(normalized)
        val host = requireHost(uri)
        val query = query(uri)
        val password = decode(uri.rawUserInfo).takeIf(String::isNotBlank)
            ?: query["auth"]?.takeIf(String::isNotBlank)
            ?: throw ImportException("В Hysteria2 отсутствует пароль.")
        val obfsType = query["obfs"]?.lowercase()
        if (obfsType != null && obfsType !in setOf("none", "salamander")) {
            throw ImportException("Hysteria2 obfs '$obfsType' пока не поддерживается.")
        }
        return ProtocolOutboundBuilders.hysteria2(
            displayName = displayName(uri, "Hysteria2 ${index + 1}"),
            server = host,
            serverPort = requirePort(uri),
            password = password,
            tls = TlsSettings(
                enabled = true,
                serverName = query["sni"] ?: query["peer"] ?: host,
                insecure = query.boolean("insecure") || query.boolean("allowInsecure"),
                alpn = query.csv("alpn"),
            ),
            obfsPassword = if (obfsType == "salamander") {
                query["obfs-password"] ?: query["obfs_password"]
            } else {
                null
            },
            upMbps = query["upmbps"]?.toIntOrNull(),
            downMbps = query["downmbps"]?.toIntOrNull(),
        )
    }

    private fun parseTuic(link: String, index: Int): ManagedServer {
        val uri = URI(link)
        val host = requireHost(uri)
        val query = query(uri)
        val credentials = decode(uri.rawUserInfo)
        val uuid = credentials.substringBefore(':').takeIf(String::isNotBlank)
            ?: throw ImportException("В TUIC отсутствует UUID.")
        val password = credentials.substringAfter(':', "").takeIf(String::isNotBlank)
            ?: throw ImportException("В TUIC отсутствует пароль.")
        return ProtocolOutboundBuilders.tuic(
            displayName = displayName(uri, "TUIC ${index + 1}"),
            server = host,
            serverPort = requirePort(uri),
            uuid = uuid,
            password = password,
            congestionControl = query["congestion_control"] ?: query["congestion-control"],
            udpRelayMode = query["udp_relay_mode"] ?: query["udp-relay-mode"],
            zeroRttHandshake = query.boolean("zero_rtt_handshake") || query.boolean("zero-rtt-handshake"),
            heartbeat = query["heartbeat"],
            tls = TlsSettings(
                enabled = true,
                serverName = query["sni"] ?: host,
                insecure = query.boolean("allow_insecure") ||
                    query.boolean("allowInsecure") ||
                    query.boolean("insecure"),
                alpn = query.csv("alpn"),
            ),
        )
    }

    private fun decodeCredentials(value: String): String {
        val decoded = decode(value)
        return if (':' in decoded) decoded else decodeBase64(value)
    }

    private fun tls(
        query: Map<String, String>,
        host: String,
        defaultEnabled: Boolean = false,
    ): TlsSettings {
        val security = query["security"]?.lowercase()
        val enabled = defaultEnabled || security == "tls" || security == "reality"
        return TlsSettings(
            enabled = enabled,
            serverName = query["sni"] ?: query["serverName"] ?: if (enabled) host else null,
            insecure = query["allowInsecure"] == "1",
            utlsFingerprint = query["fp"],
            realityPublicKey = query["pbk"] ?: query["publicKey"],
            realityShortId = query["sid"] ?: query["shortId"],
            alpn = query.csv("alpn"),
        )
    }

    private fun transport(
        query: Map<String, String>,
        allowXhttp: Boolean = false,
    ): TransportSettings? = when (
        val type = query["type"]?.lowercase().orEmpty()
    ) {
        "", "tcp", "none" -> null
        "ws", "http", "httpupgrade" -> TransportSettings(
            type = type,
            path = query["path"],
            host = query["host"],
        )
        "grpc" -> TransportSettings(
            type = type,
            serviceName = query["serviceName"] ?: query["service_name"],
        )
        "xhttp" -> if (allowXhttp) {
            TransportSettings(
                type = type,
                path = query["path"],
                host = query["host"],
                mode = query["mode"],
                xhttpOptions = xhttpOptions(query["extra"]),
            )
        } else {
            throw ImportException("Transport '$type' пока не поддерживается.")
        }
        else -> throw ImportException("Transport '$type' пока не поддерживается.")
    }

    private fun xhttpOptions(encoded: String?): JsonObject? {
        if (encoded.isNullOrBlank()) return null
        val source = try {
            JsonConfig.parse(decodeBase64(encoded)) as? JsonObject
                ?: throw ImportException("XHTTP extra должен быть JSON-объектом.")
        } catch (error: ImportException) {
            throw error
        } catch (error: Exception) {
            throw ImportException("Не удалось разобрать XHTTP extra.", cause = error)
        }
        val options = linkedMapOf<String, kotlinx.serialization.json.JsonElement>()

        source.boolean("noGRPCHeader")?.let { options["no_grpc_header"] = JsonPrimitive(it) }
        source.string("xPaddingBytes")?.let { options["x_padding_bytes"] = JsonPrimitive(it) }
        source.string("scMaxEachPostBytes")
            ?.let { options["sc_max_each_post_bytes"] = JsonPrimitive(it) }
        source.string("scMinPostsIntervalMs")
            ?.let { options["sc_min_posts_interval_ms"] = JsonPrimitive(it) }
        source.string("scStreamUpServerSecs")
            ?.let { options["sc_stream_up_server_secs"] = JsonPrimitive(it) }

        (source["xmux"] as? JsonObject)?.let { xmuxSource ->
            val xmux = linkedMapOf<String, kotlinx.serialization.json.JsonElement>()
            XMUX_RANGE_FIELDS.forEach { (sourceKey, targetKey) ->
                xmuxSource.string(sourceKey)?.let { xmux[targetKey] = JsonPrimitive(it) }
            }
            xmuxSource.long("hKeepAlivePeriod")
                ?.let { xmux["h_keep_alive_period"] = JsonPrimitive(it) }
            if (xmux.isNotEmpty()) options["xmux"] = JsonObject(xmux)
        }

        return options.takeIf(Map<*, *>::isNotEmpty)?.let(::JsonObject)
    }

    private fun query(uri: URI): Map<String, String> = uri.rawQuery
        .orEmpty()
        .split('&')
        .filter(String::isNotBlank)
        .associate { part ->
            val key = decode(part.substringBefore('='))
            val value = decode(part.substringAfter('=', ""))
            key to value
        }

    private fun displayName(uri: URI, fallback: String): String =
        decode(uri.rawFragment.orEmpty()).ifBlank { fallback }

    private fun Map<String, String>.boolean(key: String): Boolean =
        this[key]?.lowercase() in setOf("1", "true", "yes", "on")

    private fun Map<String, String>.csv(key: String): List<String> =
        this[key].orEmpty().split(',').map(String::trim).filter(String::isNotBlank)

    private fun requireHost(uri: URI): String = uri.host
        ?.takeIf(String::isNotBlank)
        ?.removeSurrounding("[", "]")
        ?: throw ImportException("В ссылке отсутствует сервер.")

    private fun requirePort(uri: URI): Int = uri.port
        .takeIf { it in 1..65535 }
        ?: throw ImportException("В ссылке отсутствует корректный порт.")

    private fun JsonObject.text(key: String): String? =
        (this[key] as? JsonPrimitive)?.contentOrNull

    private fun JsonObject.number(key: String): Int? {
        val primitive = this[key] as? JsonPrimitive ?: return null
        return primitive.intOrNull ?: primitive.contentOrNull?.toIntOrNull()
    }

    private fun JsonObject.string(key: String): String? =
        (this[key] as? JsonPrimitive)?.contentOrNull

    private fun JsonObject.boolean(key: String): Boolean? =
        (this[key] as? JsonPrimitive)?.booleanOrNull

    private fun JsonObject.long(key: String): Long? =
        (this[key] as? JsonPrimitive)?.longOrNull

    private val XMUX_RANGE_FIELDS = mapOf(
        "cMaxReuseTimes" to "c_max_reuse_times",
        "maxConcurrency" to "max_concurrency",
        "maxConnections" to "max_connections",
        "hMaxRequestTimes" to "h_max_request_times",
        "hMaxReusableSecs" to "h_max_reusable_secs",
    )
}

class AndroidImportReader(private val context: Context) {
    fun readDocument(uri: Uri): String {
        val input = context.contentResolver.openInputStream(uri)
            ?: throw ImportException("Не удалось открыть выбранный файл.")
        return try {
            input.use { stream ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                var total = 0
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    total += count
                    if (total > MAX_IMPORT_BYTES) {
                        throw ImportException("Файл больше 4 МБ.")
                    }
                    output.write(buffer, 0, count)
                }
                output.toString(StandardCharsets.UTF_8.name())
            }
        } catch (error: IOException) {
            throw ImportException("Ошибка чтения выбранного файла.", cause = error)
        }
    }

    fun readClipboardAfterUserAction(): String {
        val clipboard = context.getSystemService(ClipboardManager::class.java)
            ?: throw ImportException("Буфер обмена недоступен.")
        val clip = clipboard.primaryClip
            ?: throw ImportException("Буфер обмена пуст.")
        if (clip.itemCount == 0) throw ImportException("Буфер обмена пуст.")
        val text = clip.getItemAt(0).coerceToText(context)?.toString()
            ?.takeIf(String::isNotBlank)
            ?: throw ImportException("В буфере нет текста.")
        if (text.toByteArray(Charsets.UTF_8).size > MAX_IMPORT_BYTES) {
            throw ImportException("Текст в буфере больше 4 МБ.")
        }
        return text
    }

    fun clearClipboardSafely() {
        runCatching {
            val clipboard = context.getSystemService(ClipboardManager::class.java) ?: return
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                clipboard.clearPrimaryClip()
            } else {
                clipboard.setPrimaryClip(android.content.ClipData.newPlainText("", ""))
            }
        }
    }

    fun documentDisplayName(uri: Uri): String? = runCatching {
        context.contentResolver.query(
            uri,
            arrayOf(OpenableColumns.DISPLAY_NAME),
            null,
            null,
            null,
        )?.use { cursor ->
            if (!cursor.moveToFirst()) return@use null
            cursor.getString(cursor.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME))
                ?.trim()
                ?.takeIf(String::isNotEmpty)
                ?.take(MAX_DISPLAY_NAME_LENGTH)
        }
    }.getOrNull() ?: uri.lastPathSegment
        ?.substringAfterLast('/')
        ?.trim()
        ?.takeIf(String::isNotEmpty)
        ?.take(MAX_DISPLAY_NAME_LENGTH)

    private companion object {
        const val MAX_IMPORT_BYTES = 4 * 1024 * 1024
        const val MAX_DISPLAY_NAME_LENGTH = 160
    }
}

internal fun decodeBase64(input: String): String {
    val compact = input.filterNot(Char::isWhitespace)
    val padded = compact + "=".repeat((4 - compact.length % 4) % 4)
    val decoder = if ('-' in padded || '_' in padded) Base64.getUrlDecoder() else Base64.getDecoder()
    return String(decoder.decode(padded), Charsets.UTF_8)
}

private fun decode(value: String): String =
    URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8.name())
