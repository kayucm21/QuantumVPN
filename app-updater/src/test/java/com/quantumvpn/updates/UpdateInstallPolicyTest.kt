package com.quantumvpn.updates

import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateInstallPolicyTest {
    @Test
    fun `same signer and proven rotation are compatible`() {
        assertTrue(UpdateInstallPolicy.signingCompatible(signing("old"), signing("old")))
        assertTrue(
            UpdateInstallPolicy.signingCompatible(
                signing("old"),
                SigningIdentity(setOf("new"), setOf("old", "new"), false),
            ),
        )
        assertFalse(UpdateInstallPolicy.signingCompatible(signing("old"), signing("other")))
    }

    @Test
    fun `multiple signers require exact current set`() {
        val installed = SigningIdentity(setOf("a", "b"), setOf("a", "b"), true)
        assertTrue(
            UpdateInstallPolicy.signingCompatible(
                installed,
                SigningIdentity(setOf("b", "a"), setOf("b", "a"), true),
            ),
        )
        assertFalse(
            UpdateInstallPolicy.signingCompatible(
                installed,
                SigningIdentity(setOf("a"), setOf("a"), false),
            ),
        )
    }

    @Test
    fun `package signature metadata and downgrade are enforced together`() {
        val installed = identity("app", 10, "1.0", signing("key"))
        val valid = identity("app", 11, "1.1", signing("key"))
        val metadata = metadata("app", 11, "1.1")
        UpdateInstallPolicy.requireCompatible(installed, valid, metadata, deviceSdk = 36)

        assertThrows(UpdateException::class.java) {
            UpdateInstallPolicy.requireCompatible(installed, valid.copy(versionCode = 10), metadata.copy(versionCode = 10), 36)
        }
        assertThrows(UpdateException::class.java) {
            UpdateInstallPolicy.requireCompatible(installed, valid.copy(packageName = "other"), metadata, 36)
        }
        assertThrows(UpdateException::class.java) {
            UpdateInstallPolicy.requireCompatible(installed, valid.copy(signing = signing("other")), metadata, 36)
        }
        assertThrows(UpdateException::class.java) {
            UpdateInstallPolicy.requireCompatible(installed, valid.copy(minSdk = 37), metadata, 36)
        }
    }

    private fun signing(value: String) = SigningIdentity(setOf(value), setOf(value), false)

    private fun identity(packageName: String, code: Long, name: String, signing: SigningIdentity) =
        ApkIdentity(packageName, name, code, 26, signing)

    private fun metadata(packageName: String, code: Long, name: String) = ReleaseMetadata(
        versionName = name,
        versionCode = code,
        applicationId = packageName,
        coreTag = "v1",
        coreCommit = "0".repeat(40),
        abi = listOf("arm64-v8a"),
        apkFile = "app.apk",
        apkSha256 = "0".repeat(64),
        apkSize = 1,
    )
}
