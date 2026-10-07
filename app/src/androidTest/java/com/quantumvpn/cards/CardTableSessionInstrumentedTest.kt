package com.quantumvpn.cards

import android.content.Context
import android.util.Base64
import androidx.test.platform.app.InstrumentationRegistry
import com.quantumvpn.security.SecureVault
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Test

/** Storage-only verification: no live operator endpoint or device networking. */
class CardTableSessionInstrumentedTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val store get() = context.getSharedPreferences("card_table_resume", Context.MODE_PRIVATE)

    @After fun clearOnlyCardResume() { CardTableRepository(context).clearSession() }

    private fun snapshot(expiresAt: Long = System.currentTimeMillis() / 1000L + 3600L): CardTableSnapshot {
        val body = JSONObject().put("scope", "card_game").put("exp", expiresAt).toString()
        val ticket = Base64.encodeToString(body.toByteArray(), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING) + ".fixture-signature"
        return CardTableSnapshot("aabbccddeeff", ticket, "waiting", "host", "Игрок", "", "Ожидаем игрока")
    }

    @Test fun recreatedRepositoryRestoresAnEncryptedTicketWithoutNameOrCode() {
        val table = snapshot()
        CardTableRepository(context).rememberSession(table)
        val encoded = store.getString("sealed_session", null)!!
        assertEquals(setOf("sealed_session"), store.all.keys)
        assertFalse(encoded.contains(table.ticket))
        assertFalse(encoded.contains(table.name))
        val sealed = Base64.decode(encoded, Base64.NO_WRAP)
        assertTrue(SecureVault().isSealed(sealed))
        val plaintext = JSONObject(String(SecureVault().open(sealed)))
        assertEquals(setOf("ticket", "table_id", "expires_at"), plaintext.keys().asSequence().toSet())
        val restored = CardTableRepository(context).rememberedSession()!!
        assertEquals(table.tableId, restored.tableId)
        assertEquals(table.ticket, restored.ticket)
    }

    @Test fun unchangedStateDoesNotRewriteTheEncryptedResume() {
        val repository = CardTableRepository(context)
        val table = snapshot()
        repository.rememberSession(table)
        val first = store.getString("sealed_session", null)
        repository.rememberSession(table.copy(message = "Ожидание"))
        assertEquals(first, store.getString("sealed_session", null))
    }

    @Test fun expiredFinishedAndCorruptResumesAreCleared() {
        val repository = CardTableRepository(context)
        repository.rememberSession(snapshot())
        repository.rememberSession(snapshot(expiresAt = 1L))
        assertNull(repository.rememberedSession())
        assertTrue(store.all.isEmpty())
        repository.rememberSession(snapshot())
        repository.rememberSession(snapshot().copy(state = "finished", gamePhase = "finished"))
        assertNull(repository.rememberedSession())
        store.edit().putString("sealed_session", Base64.encodeToString("plaintext-ticket".toByteArray(), Base64.NO_WRAP)).commit()
        assertNull(CardTableRepository(context).rememberedSession())
        assertTrue(store.all.isEmpty())
    }
}
