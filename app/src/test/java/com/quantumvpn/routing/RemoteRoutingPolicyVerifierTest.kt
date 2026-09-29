package com.quantumvpn.routing

import java.security.MessageDigest
import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPrivateKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class RemoteRoutingPolicyVerifierTest {
    @Test
    fun `accepts canonical ed25519 policy and rejects payload tampering`() {
        val payload = Json.parseToJsonElement(
            """{"schema":1,"revision":7,"enabled":true,"profile":"proxy_all","dns":{"mode":"vpn_only","resolver":"https://dns.adguard-dns.com/dns-query"},"adblock":{"enabled":true},"rules":{"direct_domains":["bank.example"],"proxy_domains":["video.example"],"block_domains":["ads.example"],"direct_cidrs":["192.0.2.0/24"],"proxy_cidrs":["2001:db8::/32"]}}""",
        ) as JsonObject
        val canonical = RemoteRoutingPolicyVerifier.canonicalJson(payload).toByteArray()
        val key = privateKey()
        val publicKey = Base64.getUrlEncoder().withoutPadding().encodeToString(key.abyte)
        val signature = EdDSAEngine()
            .apply { initSign(key); update(canonical) }
            .sign()
        val envelope = """{"schema":1,"channel":"production","payload":${payload},"sha256":"${sha256(canonical)}","signature":"${Base64.getUrlEncoder().withoutPadding().encodeToString(signature)}","public_key":"$publicKey","signature_algorithm":"ed25519"}"""

        val accepted = RemoteRoutingPolicyVerifier.decodeAndVerify(envelope, publicKey)
        assertEquals(7L, accepted.policy.revision)
        assertEquals(RemoteRoutingProfile.ProxyAll, accepted.policy.profile)
        assertEquals(listOf("video.example"), accepted.policy.proxyDomains)

        try {
            RemoteRoutingPolicyVerifier.decodeAndVerify(envelope.replace("video.example", "evil.example"), publicKey)
            fail("Tampered policy must not verify")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }

    private fun privateKey(): EdDSAPrivateKey {
        val curve = checkNotNull(EdDSANamedCurveTable.getByName("Ed25519"))
        return EdDSAPrivateKey(EdDSAPrivateKeySpec(ByteArray(32) { (it + 1).toByte() }, curve))
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { "%02x".format(it) }
}
