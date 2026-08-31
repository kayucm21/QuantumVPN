package com.quantumvpn.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AES-GCM vault backed by Android Keystore. Plaintext legacy blobs (JSON starting with '{')
 * are accepted by [open] for one-shot migration; [seal] always writes ciphertext.
 */
class SecureVault {
    fun seal(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        val iv = cipher.iv
        val encrypted = cipher.doFinal(plain)
        return ByteBuffer.allocate(MAGIC.size + 1 + iv.size + encrypted.size).apply {
            put(MAGIC)
            put(iv.size.toByte())
            put(iv)
            put(encrypted)
        }.array()
    }

    fun open(blob: ByteArray): ByteArray {
        if (blob.isEmpty()) return blob
        if (!isSealed(blob)) return blob
        val buffer = ByteBuffer.wrap(blob)
        val magic = ByteArray(MAGIC.size)
        buffer.get(magic)
        check(magic.contentEquals(MAGIC)) { "Повреждён заголовок шифрования." }
        val ivSize = buffer.get().toInt() and 0xff
        require(ivSize in 12..32) { "Некорректный IV шифрования." }
        val iv = ByteArray(ivSize)
        buffer.get(iv)
        val encrypted = ByteArray(buffer.remaining())
        buffer.get(encrypted)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(encrypted)
    }

    fun isSealed(blob: ByteArray): Boolean =
        blob.size > MAGIC.size + 1 &&
            blob.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)

    private fun secretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = keyStore.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existing != null) return existing.secretKey

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(false)
        }
        generator.init(builder.build())
        return generator.generateKey()
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "quantumvpn_vault_v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
        val MAGIC = byteArrayOf('Q'.code.toByte(), 'V'.code.toByte(), 'N'.code.toByte(), '1'.code.toByte())
    }
}
