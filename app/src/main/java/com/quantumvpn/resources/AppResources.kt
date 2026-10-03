package com.quantumvpn.resources

import com.quantumvpn.routing.RemoteRoutingPolicyVerifier
import java.security.MessageDigest
import java.util.Base64
import kotlinx.serialization.json.*
import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec

data class ResourceImage(val sha256: String, val size: Int, val mime: String, val width: Int, val height: Int)
data class AppResources(
    val sequence: Long, val revision: Long, val texts: Map<String, String>,
    val accent: String?, val compactHome: Boolean, val assets: Map<String, ResourceImage>,
    val digest: String, val envelope: String,
) {
    fun text(key: String, fallback: String): String = texts[key] ?: fallback
}

/** Deliberately not an HTML, JavaScript, DEX, native-code or VPN configuration loader. */
object AppResourceVerifier {
    const val MAX_MANIFEST = 32 * 1024
    const val MAX_ASSET = 2 * 1024 * 1024
    private val json = Json { isLenient = false; ignoreUnknownKeys = false }
    private val hash = Regex("[0-9a-f]{64}")
    private val textLimits = mapOf("brand_name" to 32, "tagline" to 100, "welcome" to 120, "games_title" to 40, "games_subtitle" to 100)

    fun verify(raw: String, versionCode: Long, minimumSequence: Long = 0,
               pinnedKey: String = RemoteRoutingPolicyVerifier.PINNED_PUBLIC_KEY): AppResources {
        require(raw.toByteArray(Charsets.UTF_8).size <= MAX_MANIFEST) { "Пакет ресурсов превышает лимит" }
        val root = json.parseToJsonElement(raw) as? JsonObject ?: error("Неверный пакет ресурсов")
        root.only("schema", "signature_algorithm", "payload", "sha256", "signature", "public_key")
        require(root.number("schema") == 1L && root.string("signature_algorithm") == "ed25519")
        require(root.string("public_key") == pinnedKey) { "Ключ ресурсов не совпадает с ключом APK" }
        val payload = root.obj("payload")
        val canonical = RemoteRoutingPolicyVerifier.canonicalJson(payload).toByteArray(Charsets.UTF_8)
        val digest = sha256(canonical)
        require(hash.matches(root.string("sha256")) && root.string("sha256") == digest) { "SHA-256 ресурсов не совпадает" }
        val keyBytes = Base64.getUrlDecoder().decode(pinnedKey)
        val signature = Base64.getUrlDecoder().decode(root.string("signature"))
        require(keyBytes.size == 32 && signature.size == 64)
        val key = EdDSAPublicKey(EdDSAPublicKeySpec(keyBytes, EdDSANamedCurveTable.getByName("Ed25519")))
        require(EdDSAEngine(MessageDigest.getInstance("SHA-512")).run {
            initVerify(key); update(canonical); verify(signature)
        }) { "Подпись ресурсов не прошла проверку" }
        payload.only("kind", "sequence", "revision", "min_version_code", "texts", "theme", "assets")
        require(payload.string("kind") == "quantumvpn-resources-v1") { "Пакет другого назначения" }
        val sequence = payload.number("sequence")
        require(sequence in 1..Int.MAX_VALUE.toLong() && sequence >= minimumSequence) { "Устаревшая публикация ресурсов" }
        val revision = payload.number("revision")
        require(revision in 1..Int.MAX_VALUE.toLong())
        require(payload.number("min_version_code") in 1..versionCode) { "Нужна более новая версия APK" }
        val texts = payload.obj("texts").map { (key, element) ->
            val limit = textLimits[key] ?: error("Неизвестный текст ресурса")
            val value = element as? JsonPrimitive ?: error("Неверный текст ресурса")
            require(value.isString && value.content.length in 1..limit && value.content.none { it.code < 32 })
            key to value.content
        }.toMap()
        val theme = payload.obj("theme")
        theme.only("accent", "compact_home")
        val accent = theme["accent"]?.let { theme.string("accent") }
        require(accent == null || accent.matches(Regex("#[0-9A-Fa-f]{6}")))
        val compact = theme["compact_home"]?.let {
            val p = it as? JsonPrimitive ?: error("Неверный параметр оформления")
            require(!p.isString); p.booleanOrNull ?: error("Неверный параметр оформления")
        } ?: false
        val assets = payload.obj("assets")
        assets.only("logo", "background")
        val images = assets.mapValues { (_, value) ->
            val image = value as? JsonObject ?: error("Неверное изображение")
            image.only("sha256", "size", "mime", "width", "height")
            val size = image.number("size")
            val width = image.number("width")
            val height = image.number("height")
            require(size in 1..MAX_ASSET.toLong() && width in 1..1440L && height in 1..1440L)
            val sha = image.string("sha256")
            val mime = image.string("mime")
            require(hash.matches(sha) && mime in setOf("image/png", "image/jpeg"))
            ResourceImage(sha, size.toInt(), mime, width.toInt(), height.toInt())
        }
        return AppResources(sequence, revision, texts, accent, compact, images, digest, raw)
    }

    fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun JsonObject.only(vararg keys: String) = require(this.keys.all { it in keys }) { "Неизвестное поле ресурсов" }
    private fun JsonObject.obj(key: String): JsonObject = this[key] as? JsonObject ?: error("Нет '$key'")
    private fun JsonObject.string(key: String): String {
        val value = this[key] as? JsonPrimitive ?: error("Нет '$key'")
        require(value.isString); return value.content
    }
    private fun JsonObject.number(key: String): Long {
        val value = this[key] as? JsonPrimitive ?: error("Нет '$key'")
        require(!value.isString); return value.longOrNull ?: error("Неверное '$key'")
    }
}
