package com.quantumvpn.cards

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.provider.Settings
import com.quantumvpn.BuildConfig
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** A device-bound snapshot of the two-player table maintained by Quantum Control. */
data class CardTableSnapshot(
    val tableId: String,
    val ticket: String = "",
    val state: String,
    val seat: String,
    val name: String,
    val opponentName: String,
    val message: String,
    /** Virtual game points only: no purchase, withdrawal, or real-money value. */
    val qCoins: Long = 0L,
    /** The virtual stake deducted from each player after both confirm ready. */
    val stakeQCoins: Long = 0L,
    /** The complete virtual pot paid to the winner once the game ends. */
    val winnerRewardQCoins: Long = 0L,
    val gamePhase: String = "waiting",
    val hand: List<String> = emptyList(),
    val opponentCards: Int = 0,
    val tableCards: List<CardPair> = emptyList(),
    val trump: String = "",
    val deckCount: Int = 0,
    val attacker: String = "",
    val winner: String = "",
    val canReady: Boolean = false,
    val canAttack: Boolean = false,
    val canDefend: Boolean = false,
    val canTake: Boolean = false,
    val canPass: Boolean = false,
    val revision: Long = 0L,
    val discardCount: Int = 0,
    val boutLimit: Int = 6,
    val legalAttackCards: List<String> = emptyList(),
    val legalDefenses: List<CardDefense> = emptyList(),
    val hasLegalActions: Boolean = false,
) {
    val waiting: Boolean get() = state == "waiting"
    val ready: Boolean get() = state in setOf("ready", "playing", "finished")
}

data class CardPair(val attack: String, val defense: String)
data class CardDefense(val card: String, val target: Int)

/**
 * Secure, deliberately small client for the card-table lobby.
 *
 * The panel stores only a PBKDF2 hash of the access code. The code is kept in
 * Compose state while joining and is never written to SharedPreferences, logs,
 * diagnostics, or an APK resource. The returned ticket is both short-lived and
 * bound to this device by the operator panel.
 */
class CardTableRepository(context: Context) {
    private val app = context.applicationContext

    suspend fun join(accessCode: String, displayName: String): Result<CardTableSnapshot> =
        request("/api/client/cards/join", "POST", JSONObject()
            .put("access_code", accessCode)
            .put("display_name", displayName)
            .toString())

    suspend fun state(ticket: String): Result<CardTableSnapshot> {
        if (ticket.isBlank()) return Result.failure(IllegalArgumentException("Нет билета игрового стола"))
        return request("/api/client/cards/state?ticket=${java.net.URLEncoder.encode(ticket, "UTF-8")}", "GET")
    }

    suspend fun action(
        ticket: String, action: String, card: String = "", target: Int? = null,
        expectedRevision: Long? = null, actionId: String = java.util.UUID.randomUUID().toString(),
    ): Result<CardTableSnapshot> {
        require(ticket.isNotBlank()) { "Нет билета игрового стола" }
        return request(
            "/api/client/cards/action",
            "POST",
            JSONObject().put("ticket", ticket).put("action", action).put("card", card)
                .put("action_id", actionId).apply {
                    target?.let { put("target", it) }
                    expectedRevision?.let { put("expected_revision", it) }
                }.toString(),
        )
    }

    private suspend fun request(path: String, method: String, body: String? = null): Result<CardTableSnapshot> =
        withContext(Dispatchers.IO) {
            runCatching {
                val base = BuildConfig.PANEL_UPDATE_BASE_URL.trim().trimEnd('/')
                check(base.isNotBlank()) { "Игровая панель не настроена" }
                val connection = (URL(base + path).openConnection() as HttpURLConnection).apply {
                    requestMethod = method
                    instanceFollowRedirects = false
                    connectTimeout = 10_000
                    readTimeout = 15_000
                    setRequestProperty("Accept", "application/json")
                    setRequestProperty("X-Device-Id", androidIdHash())
                    setRequestProperty("X-HWID", androidIdHash())
                    setRequestProperty("X-Device-Model", Build.MODEL.take(120))
                    if (body != null) {
                        doOutput = true
                        setRequestProperty("Content-Type", "application/json; charset=utf-8")
                    }
                }
                try {
                    if (body != null) connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
                    val stream = if (connection.responseCode in 200..299) connection.inputStream else connection.errorStream
                    val raw = stream?.use { input ->
                        val output = java.io.ByteArrayOutputStream()
                        val buffer = ByteArray(4_096)
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            check(output.size() + count <= 262_144) { "Ответ игрового стола слишком большой" }
                            output.write(buffer, 0, count)
                        }
                        output.toString("UTF-8")
                    }.orEmpty()
                    if (connection.responseCode !in 200..299) {
                        val message = runCatching { JSONObject(raw).optString("message") }.getOrDefault("")
                        error(message.ifBlank { "Не удалось открыть стол (HTTP ${connection.responseCode})" })
                    }
                    parseSnapshot(raw)
                } finally {
                    connection.disconnect()
                }
            }
        }

    private fun parseSnapshot(raw: String): CardTableSnapshot {
        val payload = JSONObject(raw)
        val tableId = payload.optString("table_id")
        require(tableId.matches(Regex("[a-f0-9]{12}"))) { "Панель вернула неверный игровой стол" }
        return CardTableSnapshot(
            tableId = tableId,
            ticket = payload.optString("ticket"),
            state = payload.optString("state", "waiting"),
            seat = payload.optString("seat"),
            name = payload.optString("name"),
            opponentName = payload.optString("opponent_name"),
            message = payload.optString("message"),
            qCoins = payload.optLong("q_coins", 0L).coerceAtLeast(0L),
            stakeQCoins = payload.optLong("stake_q_coins", 0L).coerceAtLeast(0L),
            winnerRewardQCoins = payload.optLong("winner_reward_q_coins", 0L).coerceAtLeast(0L),
            gamePhase = payload.optString("game_phase", "waiting"),
            hand = buildList {
                val cards = payload.optJSONArray("hand")
                for (index in 0 until (cards?.length() ?: 0)) add(cards?.optString(index).orEmpty())
            },
            opponentCards = payload.optInt("opponent_cards", 0).coerceAtLeast(0),
            tableCards = buildList {
                val cards = payload.optJSONArray("table_cards")
                for (index in 0 until (cards?.length() ?: 0)) {
                    cards?.optJSONObject(index)?.let { pair ->
                        add(CardPair(pair.optString("attack"), pair.optString("defense")))
                    }
                }
            },
            trump = payload.optString("trump"),
            deckCount = payload.optInt("deck_count", 0).coerceAtLeast(0),
            attacker = payload.optString("attacker"),
            winner = payload.optString("winner"),
            canReady = payload.optBoolean("can_ready", false),
            canAttack = payload.optBoolean("can_attack", false),
            canDefend = payload.optBoolean("can_defend", false),
            canTake = payload.optBoolean("can_take", false),
            canPass = payload.optBoolean("can_pass", false),
            revision = payload.optLong("revision", 0L).coerceAtLeast(0L),
            discardCount = payload.optInt("discard_count", 0).coerceIn(0, 36),
            boutLimit = payload.optInt("bout_limit", 6).coerceIn(0, 6),
            legalAttackCards = buildList {
                val cards = payload.optJSONArray("legal_attack_cards")
                for (index in 0 until minOf(cards?.length() ?: 0, 36)) {
                    cards?.optString(index)?.takeIf { it.matches(Regex("(?:10|[6-9JQKA])[SHDC]")) }?.let(::add)
                }
            },
            legalDefenses = buildList {
                val choices = payload.optJSONArray("legal_defenses")
                for (index in 0 until minOf(choices?.length() ?: 0, 216)) {
                    val item = choices?.optJSONObject(index) ?: continue
                    val card = item.optString("card")
                    val target = item.optInt("target", -1)
                    if (card.matches(Regex("(?:10|[6-9JQKA])[SHDC]")) && target in 0..5) add(CardDefense(card, target))
                }
            },
            hasLegalActions = payload.has("legal_attack_cards") && payload.has("legal_defenses"),
        )
    }

    @SuppressLint("HardwareIds")
    private fun androidIdHash(): String {
        val raw = Settings.Secure.getString(app.contentResolver, Settings.Secure.ANDROID_ID).orEmpty()
        return MessageDigest.getInstance("SHA-256")
            .digest(raw.toByteArray())
            .joinToString("") { "%02x".format(it) }
            .take(16)
    }
}
