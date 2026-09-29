package com.quantumvpn.routing

import android.content.Context
import android.os.Build
import android.util.AtomicFile
import com.quantumvpn.BuildConfig
import com.quantumvpn.policy.ClientPolicyRepository
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec

/**
 * A bounded policy received from Quantum Control.  It contains names, CIDRs
 * and DNS mode only; it is never an arbitrary sing-box JSON document and can
 * therefore not install an executable route, proxy endpoint or certificate.
 */
data class RemoteRoutingPolicy(
    val revision: Long,
    val enabled: Boolean,
    val profile: RemoteRoutingProfile,
    val dns: RemoteRoutingDns,
    val adBlockEnabled: Boolean,
    val directDomains: List<String>,
    val proxyDomains: List<String>,
    val blockDomains: List<String>,
    val directCidrs: List<String>,
    val proxyCidrs: List<String>,
)

enum class RemoteRoutingProfile {
    Balanced,
    Whitelist,
    ProxyAll,
}

data class RemoteRoutingDns(
    val vpnOnly: Boolean,
    val resolver: String,
)

data class VerifiedRoutingPolicy(
    val policy: RemoteRoutingPolicy,
    val channel: String,
    val payloadSha256: String,
    val rawEnvelope: String,
)

/** Network/configuration result deliberately leaves a usable cached policy intact on failure. */
sealed interface RoutingPolicyRefreshResult {
    data class Applied(val verified: VerifiedRoutingPolicy, val fromCache: Boolean) : RoutingPolicyRefreshResult
    data class Unavailable(val message: String) : RoutingPolicyRefreshResult
}

/**
 * Verifies panel policy before it reaches a profile.  The server-advertised
 * public key is compared with [pinnedPublicKey] for diagnostics only; it is
 * never used as a source of trust.
 */
object RemoteRoutingPolicyVerifier {
    const val PINNED_PUBLIC_KEY = "lNDNapSDNgBvv0cKnsdMvQMTIIUPx_6fKnf2QoY0v7g"
    private const val MAX_POLICY_BYTES = 512 * 1024
    private const val MAX_RULES_PER_LIST = 2_000
    private const val MAX_RULES_TOTAL = 4_000
    private val json = Json { ignoreUnknownKeys = false; isLenient = false }
    private val domainLabel = Regex("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

    fun decodeAndVerify(
        raw: String,
        pinnedPublicKey: String = PINNED_PUBLIC_KEY,
    ): VerifiedRoutingPolicy {
        require(raw.toByteArray(StandardCharsets.UTF_8).size <= MAX_POLICY_BYTES) {
            "Ответ маршрутизации превышает лимит."
        }
        val root = json.parseToJsonElement(raw) as? JsonObject
            ?: error("Политика маршрутизации должна быть JSON-объектом.")
        root.requireOnly(
            "schema", "signature_algorithm", "public_key", "signature", "sha256",
            "payload", "channel", "bucket", "rollout_percent", "issued_at",
        )
        require(root.long("schema") == 1L) { "Неподдерживаемая схема политики маршрутизации." }
        require(root.string("signature_algorithm") == "ed25519") {
            "Панель не предоставила Ed25519-подпись политики."
        }
        val advertisedKey = root.string("public_key")
        require(advertisedKey == pinnedPublicKey) { "Ключ подписи панели не совпадает с ключом APK." }
        val payload = root["payload"] as? JsonObject
            ?: error("В политике нет payload.")
        val canonical = canonicalJson(payload).toByteArray(StandardCharsets.UTF_8)
        val declaredDigest = root.string("sha256")
        val actualDigest = sha256(canonical)
        require(declaredDigest.matches(Regex("[0-9a-f]{64}")) && declaredDigest == actualDigest) {
            "SHA-256 политики маршрутизации не совпадает."
        }
        val signature = decodeBase64Url(root.string("signature"), "Подпись политики некорректна.")
        val publicKey = decodeBase64Url(pinnedPublicKey, "Закреплённый ключ APK некорректен.")
        require(publicKey.size == 32 && signature.size == 64) { "Размер Ed25519-ключа или подписи некорректен." }
        require(verifyEd25519(publicKey, canonical, signature)) { "Ed25519-подпись политики не прошла проверку." }
        return VerifiedRoutingPolicy(
            policy = parsePayload(payload),
            channel = root.string("channel").takeIf { it in setOf("production", "staging") } ?: "production",
            payloadSha256 = actualDigest,
            rawEnvelope = raw,
        )
    }

    internal fun canonicalJson(element: JsonElement): String = when (element) {
        is JsonObject -> element.entries
            .sortedBy { it.key }
            .joinToString(prefix = "{", postfix = "}", separator = ",") { (key, value) ->
                json.encodeToString(JsonPrimitive(key)) + ":" + canonicalJson(value)
            }
        is JsonArray -> element.joinToString(prefix = "[", postfix = "]", separator = ",") { canonicalJson(it) }
        is JsonPrimitive -> json.encodeToString(element)
    }

    private fun parsePayload(payload: JsonObject): RemoteRoutingPolicy {
        payload.requireOnly("schema", "revision", "enabled", "profile", "dns", "adblock", "rules")
        require(payload.long("schema") == 1L) { "Неподдерживаемая схема payload маршрутизации." }
        val revision = payload.long("revision")
        require(revision in 1..Int.MAX_VALUE.toLong()) { "Некорректная ревизия маршрутизации." }
        val enabled = payload.boolean("enabled")
        val profile = when (payload.string("profile")) {
            "balanced" -> RemoteRoutingProfile.Balanced
            "whitelist" -> RemoteRoutingProfile.Whitelist
            "proxy_all" -> RemoteRoutingProfile.ProxyAll
            else -> error("Неизвестный профиль маршрутизации.")
        }
        val dns = payload["dns"] as? JsonObject ?: error("Нет DNS-политики маршрутизации.")
        dns.requireOnly("mode", "resolver")
        val dnsMode = dns.string("mode")
        require(dnsMode in setOf("vpn_only", "system")) { "Неизвестный режим DNS маршрутизации." }
        val resolver = dns.string("resolver", optional = true)
        if (resolver.isNotBlank()) validateResolver(resolver)
        val adblock = payload["adblock"] as? JsonObject ?: error("Нет adblock-политики маршрутизации.")
        val rules = payload["rules"] as? JsonObject ?: error("Нет списков маршрутизации.")
        adblock.requireOnly("enabled")
        rules.requireOnly(
            "direct_domains", "proxy_domains", "block_domains", "direct_cidrs", "proxy_cidrs",
        )
        val directDomains = domains(rules, "direct_domains")
        val proxyDomains = domains(rules, "proxy_domains")
        val blockDomains = domains(rules, "block_domains")
        val directCidrs = cidrs(rules, "direct_cidrs")
        val proxyCidrs = cidrs(rules, "proxy_cidrs")
        val total = directDomains.size + proxyDomains.size + blockDomains.size + directCidrs.size + proxyCidrs.size
        require(total <= MAX_RULES_TOTAL) { "В политике слишком много правил." }
        return RemoteRoutingPolicy(
            revision = revision,
            enabled = enabled,
            profile = profile,
            dns = RemoteRoutingDns(vpnOnly = dnsMode == "vpn_only", resolver = resolver),
            adBlockEnabled = adblock.boolean("enabled"),
            directDomains = directDomains,
            proxyDomains = proxyDomains,
            blockDomains = blockDomains,
            directCidrs = directCidrs,
            proxyCidrs = proxyCidrs,
        )
    }

    private fun domains(rules: JsonObject, field: String): List<String> =
        strings(rules, field).also { values ->
            values.forEach(::validateDomain)
        }

    private fun cidrs(rules: JsonObject, field: String): List<String> =
        strings(rules, field).also { values ->
            values.forEach(::validateCidr)
        }

    private fun strings(parent: JsonObject, field: String): List<String> {
        val array = parent[field] as? JsonArray ?: error("В политике нет '$field'.")
        require(array.size <= MAX_RULES_PER_LIST) { "Список '$field' превышает лимит." }
        val values = array.map {
            (it as? JsonPrimitive)?.contentOrNull?.trim()?.lowercase()
                ?.takeIf(String::isNotBlank)
                ?: error("Некорректное значение '$field'.")
        }
        require(values.distinct().size == values.size) { "Список '$field' содержит дубликаты." }
        return values
    }

    private fun validateDomain(domain: String) {
        require(domain.length in 3..253 && '.' in domain && domain.none(Char::isWhitespace)) {
            "Некорректный домен в политике."
        }
        require(domain.split('.').all { domainLabel.matches(it) }) { "Некорректный домен в политике." }
    }

    private fun validateCidr(cidr: String) {
        val parts = cidr.split('/', limit = 2)
        require(parts.size == 2 && parts[0].matches(Regex("[0-9a-fA-F:.]+"))) {
            "Некорректный CIDR в политике."
        }
        val address = runCatching { java.net.InetAddress.getByName(parts[0]) }.getOrNull()
            ?: error("Некорректный CIDR в политике.")
        val prefix = parts[1].toIntOrNull() ?: error("Некорректный CIDR в политике.")
        require(prefix in 0..if (address.address.size == 4) 32 else 128) {
            "Некорректный CIDR в политике."
        }
    }

    private fun validateResolver(value: String) {
        val uri = runCatching { URI(value) }.getOrNull() ?: error("Некорректный DoH resolver.")
        require(uri.scheme == "https" && !uri.host.isNullOrBlank() && uri.userInfo == null && uri.fragment == null) {
            "DoH resolver должен быть HTTPS URL без учётных данных."
        }
    }

    private fun JsonObject.string(key: String, optional: Boolean = false): String {
        val value = (this[key] as? JsonPrimitive)?.contentOrNull?.trim()
        if (optional) return value.orEmpty()
        return value?.takeIf(String::isNotEmpty) ?: error("В политике нет '$key'.")
    }

    private fun JsonObject.long(key: String): Long =
        (this[key] as? JsonPrimitive)?.contentOrNull?.toLongOrNull()
            ?: error("В политике нет корректного '$key'.")

    private fun JsonObject.boolean(key: String): Boolean =
        (this[key] as? JsonPrimitive)?.contentOrNull?.toBooleanStrictOrNull()
            ?: error("В политке нет корректного '$key'.")

    private fun JsonObject.requireOnly(vararg allowed: String) {
        val unexpected = keys - allowed.toSet()
        require(unexpected.isEmpty()) { "Политика содержит неподдерживаемые поля." }
    }

    private fun decodeBase64Url(value: String, message: String): ByteArray =
        runCatching { Base64.getUrlDecoder().decode(value) }.getOrElse { error(message) }

    private fun verifyEd25519(publicKey: ByteArray, payload: ByteArray, signature: ByteArray): Boolean =
        runCatching {
            val curve = checkNotNull(EdDSANamedCurveTable.getByName("Ed25519"))
            val key = EdDSAPublicKey(EdDSAPublicKeySpec(publicKey, curve))
            // EdDSAEngine's default SHA-512 implementation is portable across
            // Android API 26+ and JVM unit tests.  The EdDSA provider exposes
            // the signature primitive, not a SHA-512 MessageDigest provider.
            EdDSAEngine().run {
                initVerify(key)
                update(payload)
                verify(signature)
            }
        }.getOrDefault(false)

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { "%02x".format(it) }
}

/**
 * Fetches a policy only from the configured panel and keeps a verified last
 * known good envelope in no-backup storage.  There is no worker or timer here:
 * callers invoke it on app open, an explicit refresh, or a meaningful network
 * transition while the VPN service is active.
 */
class RemoteRoutingPolicyRepository(
    context: Context,
    private val baseUrl: String = BuildConfig.PANEL_UPDATE_BASE_URL,
    private val deviceId: () -> String = { ClientPolicyRepository.resolveAndroidId(context) },
) {
    private val cacheFile = AtomicFile(File(context.noBackupFilesDir, "routing/policy-v1.json"))
    private val mutex = Mutex()

    suspend fun refresh(): RoutingPolicyRefreshResult = mutex.withLock {
        if (baseUrl.isBlank()) return@withLock cachedOrUnavailable("Панель маршрутизации не настроена.")
        try {
            val raw = withContext(Dispatchers.IO) { fetch() }
            val verified = RemoteRoutingPolicyVerifier.decodeAndVerify(raw)
            writeCache(verified.rawEnvelope)
            RoutingPolicyRefreshResult.Applied(verified, fromCache = false)
        } catch (error: Exception) {
            cachedOrUnavailable(error.message ?: "Не удалось получить политику маршрутизации.")
        }
    }

    fun cached(): RoutingPolicyRefreshResult? = runCatching {
        val file = cacheFile.baseFile
        if (!file.isFile) return null
        RoutingPolicyRefreshResult.Applied(
            RemoteRoutingPolicyVerifier.decodeAndVerify(file.readText(StandardCharsets.UTF_8)),
            fromCache = true,
        )
    }.getOrNull()

    private fun cachedOrUnavailable(reason: String): RoutingPolicyRefreshResult =
        cached() ?: RoutingPolicyRefreshResult.Unavailable(reason.take(240))

    private fun fetch(): String {
        val endpoint = "${baseUrl.trimEnd('/')}/api/client/routing"
        require(endpoint.startsWith("https://")) { "Политика маршрутизации доступна только по HTTPS." }
        val connection = (URL(endpoint).openConnection() as HttpURLConnection).apply {
            connectTimeout = 12_000
            readTimeout = 20_000
            requestMethod = "GET"
            instanceFollowRedirects = false
            setRequestProperty("Accept", "application/json")
            deviceId().takeIf(String::isNotBlank)?.let { setRequestProperty("x-hwid", it) }
            setRequestProperty("x-device-os", "android")
            setRequestProperty("x-device-model", Build.MODEL.take(120))
        }
        try {
            require(connection.responseCode in 200..299) { "Панель вернула HTTP ${connection.responseCode}." }
            require(connection.contentLength <= 512 * 1024) { "Ответ маршрутизации превышает лимит." }
            return connection.inputStream.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    require(output.size() + count <= 512 * 1024) { "Ответ маршрутизации превышает лимит." }
                    output.write(buffer, 0, count)
                }
                output.toString(StandardCharsets.UTF_8.name())
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun writeCache(raw: String) {
        val output = cacheFile.startWrite()
        try {
            output.write(raw.toByteArray(StandardCharsets.UTF_8))
            output.fd.sync()
            cacheFile.finishWrite(output)
        } catch (error: Throwable) {
            cacheFile.failWrite(output)
            throw error
        }
    }
}
