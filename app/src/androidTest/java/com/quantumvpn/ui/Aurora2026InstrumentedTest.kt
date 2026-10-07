package com.quantumvpn.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import com.quantumvpn.cards.CardDefense
import com.quantumvpn.cards.CardPair
import com.quantumvpn.cards.CardTableSnapshot
import com.quantumvpn.community.CommunityMessage
import com.quantumvpn.community.InboxEntry
import com.quantumvpn.community.NotificationInboxScreen
import com.quantumvpn.community.SupportCenterScreen
import com.quantumvpn.community.SupportThread
import com.quantumvpn.policy.ClientPolicy
import com.quantumvpn.ui.theme.QuantumVpnTheme
import com.quantumvpn.vpn.VpnSessionStats
import com.quantumvpn.updates.UpdateState
import org.junit.Rule
import org.junit.Test

/** Independent screen tests: no live subscription/VPN connection or data clearing. */
class Aurora2026InstrumentedTest {
    @get:Rule val compose = createComposeRule()

    @Test fun connectServerAndGameActionsAreRealButtons() {
        var connect = 0
        var games = 0
        compose.setContent {
            QuantumVpnTheme(darkTheme = true) {
                V2Home(ClientPolicy(), false, false, true, "Тестовый сервер", 52, true, 60, VpnSessionStats(),
                    onConnect = { connect++ }, onServers = {}, onSettings = {}, onCards = { games++ },
                    reduceMotion = true, onNotifications = {}, pingMeasured = true)
            }
        }
        compose.onNodeWithText("Подключиться").performClick()
        compose.runOnIdle { check(connect == 1) }
        compose.onNodeWithTag("home-games").performScrollTo().performClick()
        compose.runOnIdle { check(games == 1) }
    }

    @Test fun startupDoesNotShowSimulatedPercentAndFinishesOnlyWhenReady() {
        var finished = false
        compose.setContent {
            QuantumVpnTheme {
                AuroraStartup2026(false, UpdateState.Checking("Stable"), 0, true) { finished = true }
            }
        }
        compose.onNodeWithText("Проверяем обновления").assertIsDisplayed()
        compose.onAllNodes(hasText("86%", substring = true)).assertCountEquals(0)
        compose.runOnIdle { check(!finished) }
    }

    private fun cardSnapshot() = CardTableSnapshot(
        tableId = "aabbccddeeff", ticket = "", state = "playing", seat = "guest",
        name = "Игрок", opponentName = "Соперник", message = "Ваш ход", gamePhase = "playing",
        qCoins = 1200, trump = "AC", deckCount = 12, attacker = "host", revision = 4,
        hand = listOf("7S", "8H", "9D"), opponentCards = 4, hasLegalActions = true,
    )

    private fun renderCardTable(
        table: CardTableSnapshot, busy: Boolean = false,
        onAction: (String, String) -> Unit = { _, _ -> },
        onDefend: (String, Int) -> Unit = { _, _ -> },
    ) {
        compose.setContent {
            QuantumVpnTheme(darkTheme = true) {
                Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
                    V2DurakTablePreview(table, busy, onAction, onDefend)
                }
            }
        }
    }

    @Test fun waitingLobbyDoesNotExposePassTakeOrPlayableCards() {
        val session = V2CardSession().apply {
            snapshot.value = cardSnapshot().copy(state = "waiting", gamePhase = "waiting", opponentName = "",
                hand = emptyList(), canAttack = true, canTake = true, canPass = true,
                message = "Ожидаем второго игрока")
        }
        compose.setContent { QuantumVpnTheme { V2Cards(onBack = {}, session = session) } }
        compose.onNodeWithText("Ожидаем второго игрока").assertExists()
        compose.onAllNodesWithText("Беру").assertCountEquals(0)
        compose.onAllNodesWithText("Отбой").assertCountEquals(0)
        compose.onAllNodesWithText("Пас").assertCountEquals(0)
        compose.onNodeWithTag("cards-table").assertDoesNotExist()
    }

    @Test fun readyLobbyRequiresConfirmationBeforeShowingGameActions() {
        val session = V2CardSession().apply {
            snapshot.value = cardSnapshot().copy(state = "ready", gamePhase = "ready", hand = emptyList(),
                canReady = true, canAttack = true, canTake = true, canPass = true,
                message = "Оба игрока должны подтвердить готовность")
        }
        compose.setContent { QuantumVpnTheme { V2Cards(onBack = {}, session = session) } }
        compose.onNodeWithText("Готов к раздаче").assertExists().assertIsEnabled()
        compose.onAllNodesWithText("Беру").assertCountEquals(0)
        compose.onAllNodesWithText("Отбой").assertCountEquals(0)
        compose.onNodeWithTag("cards-table").assertDoesNotExist()
    }

    @Test fun defenderSelectsUncoveredPairAndOnlyMatchingLegalCard() {
        var defended: Pair<String, Int>? = null
        renderCardTable(cardSnapshot().copy(
            tableCards = listOf(CardPair("6H", ""), CardPair("6S", "")),
            canDefend = true, canTake = true,
            legalDefenses = listOf(CardDefense("8H", 0), CardDefense("7S", 1)),
        ), onDefend = { card, target -> defended = card to target })
        compose.onNodeWithContentDescription("Карта 6 ♠").performScrollTo().performClick()
        compose.onNodeWithText("Отбить эту").assertExists()
        compose.onNodeWithContentDescription("Карта 8 ♥").assertIsNotEnabled()
        compose.onNodeWithContentDescription("Карта 9 ♦").assertIsNotEnabled()
        compose.onNodeWithContentDescription("Карта 7 ♠").assertIsEnabled().performScrollTo().performClick()
        compose.runOnIdle { check(defended == null) }
        compose.onNodeWithTag("cards-defend").assertIsEnabled().performScrollTo().performClick()
        compose.runOnIdle { check(defended == ("7S" to 1)) }
        compose.onNodeWithTag("cards-pass").assertIsNotEnabled()
    }

    @Test fun attackerCannotTapAnIllegalThrowInCard() {
        var attack = ""
        renderCardTable(cardSnapshot().copy(seat = "host", hand = listOf("6H", "9D"),
            tableCards = listOf(CardPair("6C", "7C")), canAttack = true, canPass = true,
            legalAttackCards = listOf("6H")),
            onAction = { action, card -> if (action == "attack") attack = card })
        compose.onNodeWithContentDescription("Карта 9 ♦").assertIsNotEnabled()
        compose.onNodeWithContentDescription("Карта 6 ♥").assertIsEnabled().performScrollTo().performClick()
        compose.runOnIdle { check(attack == "6H") }
        compose.onNodeWithTag("cards-pass").assertIsEnabled()
    }

    @Test fun defenderWithoutBeatingCardCanTakeAndCannotPass() {
        var action = ""
        renderCardTable(cardSnapshot().copy(hand = listOf("9D"), tableCards = listOf(CardPair("AH", "")),
            canDefend = false, canTake = true, legalDefenses = emptyList()),
            onAction = { selected, _ -> action = selected })
        compose.onNodeWithContentDescription("Карта 9 ♦").assertIsNotEnabled()
        compose.onNodeWithTag("cards-pass").assertIsNotEnabled()
        compose.onNodeWithText("Нет карты для защиты — нажмите «Беру».").assertExists()
        compose.onNodeWithText("Беру").assertIsEnabled().performScrollTo().performClick()
        compose.runOnIdle { check(action == "take") }
    }

    @Test fun pendingRequestDisablesCardTakeAndEndBoutDoubleClicks() {
        renderCardTable(cardSnapshot().copy(tableCards = listOf(CardPair("6S", "")),
            canDefend = true, canTake = true, legalDefenses = listOf(CardDefense("7S", 0))), busy = true)
        compose.onNodeWithContentDescription("Карта 7 ♠").assertIsNotEnabled()
        compose.onNodeWithContentDescription("Карта 6 ♠").assertIsNotEnabled()
        compose.onNodeWithTag("cards-defend").assertIsNotEnabled()
        compose.onNodeWithText("Беру").assertIsNotEnabled()
        compose.onNodeWithTag("cards-pass").assertIsNotEnabled()
    }

    @Test fun defenderCannotUsePassEvenIfAnObsoleteFlagSaysItIsAllowed() {
        renderCardTable(cardSnapshot().copy(tableCards = listOf(CardPair("6S", "7S")),
            canAttack = true, canPass = true, canTake = true, legalAttackCards = listOf("9D")))
        compose.onNodeWithTag("cards-pass").assertIsNotEnabled()
        compose.onNodeWithContentDescription("Карта 9 ♦").assertIsNotEnabled()
        compose.onNodeWithText("Все карты отбиты. Ждём подкидку или отбой соперника.").assertExists()
        compose.onAllNodesWithText("Нет карты для защиты — нажмите «Беру».").assertCountEquals(0)
    }

    @Test fun selectedDefenseIsClearedWhenTheAuthoritativeRevisionChanges() {
        val current = androidx.compose.runtime.mutableStateOf(cardSnapshot().copy(
            tableCards = listOf(CardPair("6S", "")), canDefend = true, canTake = true,
            legalDefenses = listOf(CardDefense("7S", 0))))
        compose.setContent {
            QuantumVpnTheme {
                Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
                    V2DurakTablePreview(current.value, false, { _, _ -> })
                }
            }
        }
        compose.onNodeWithContentDescription("Карта 7 ♠").performScrollTo().performClick()
        compose.onNodeWithTag("cards-defend").assertIsEnabled()
        compose.runOnIdle { current.value = current.value.copy(revision = current.value.revision + 1) }
        compose.onNodeWithTag("cards-defend").assertIsNotEnabled()
    }

    @Test fun disconnectedTableCannotSubmitCardsOrEndABout() {
        val session = V2CardSession().apply {
            snapshot.value = cardSnapshot().copy(tableCards = listOf(CardPair("6S", "")),
                canDefend = true, canTake = true, legalDefenses = listOf(CardDefense("7S", 0)))
            synchronized.value = false
        }
        compose.setContent { QuantumVpnTheme { V2Cards(onBack = {}, session = session) } }
        compose.onNodeWithContentDescription("Карта 7 ♠").assertIsNotEnabled()
        compose.onNodeWithText("Беру").assertIsNotEnabled()
        compose.onNodeWithTag("cards-pass").assertIsNotEnabled()
    }

    @Test fun expiredWaitingRoomCanReturnToCodeEntryWithoutStartingAParty() {
        val session = V2CardSession().apply {
            snapshot.value = cardSnapshot().copy(state = "expired", gamePhase = "unavailable", opponentName = "",
                hand = emptyList(), message = "Время ожидания истекло")
        }
        compose.setContent { QuantumVpnTheme { V2Cards(onBack = {}, session = session) } }
        compose.onNodeWithText("Комната недоступна").assertExists()
        compose.onNodeWithText("Войти по коду").performScrollTo().performClick()
        compose.onNodeWithTag("cards-join").assertExists().assertIsNotEnabled()
        compose.onNodeWithTag("cards-table").assertDoesNotExist()
    }

    @Test fun realDiscardAndDeckCountsAreVisibleAtTable() {
        renderCardTable(cardSnapshot().copy(discardCount = 18, deckCount = 3))
        compose.onNodeWithTag("cards-discard").assertTextEquals("♠ Отбой 18")
        compose.onNodeWithText("Колода 3").assertExists()
    }

    @Test fun offlineSupportDefaultsHaveNoSecretFieldsAndCannotSendEmptyMessage() {
        compose.setContent {
            QuantumVpnTheme {
                SupportCenterScreen(onBack = {}, networkEnabled = false)
            }
        }
        compose.onNodeWithTag("support-center").assertExists()
        compose.onNodeWithText("Поддержка QuantumVPN").assertExists()
        compose.onNodeWithTag("support-send").assertIsNotEnabled()
        compose.onAllNodes(hasText("Пароль администратора", substring = true)).assertCountEquals(0)
        compose.onAllNodes(hasText("Токен", substring = true)).assertCountEquals(0)
        compose.onAllNodesWithText("Код доступа").assertCountEquals(0)
        compose.onNodeWithTag("support-center").performScrollToNode(hasTestTag("quality-consent"))
        compose.onNodeWithTag("quality-consent").assertIsNotEnabled()
    }

    @Test fun offlineSupportDisplaysOperatorReplyWithoutDiagnosticContents() {
        val conversation = SupportThread(7, "Соединение обрывается", "closed", 1_700_000_000,
            listOf(CommunityMessage(1, "user", "Проверьте соединение", 1_700_000_000, hasDiagnostic = true),
                CommunityMessage(2, "operator", "Исправили сервер. Переподключите VPN", 1_700_000_001)))
        compose.setContent {
            QuantumVpnTheme {
                SupportCenterScreen(onBack = {}, networkEnabled = false, initialThread = conversation)
            }
        }
        compose.onNodeWithTag("support-center").performScrollToNode(hasText("Прикреплена обезличенная диагностика"))
        compose.onNodeWithText("Прикреплена обезличенная диагностика").assertIsDisplayed()
        compose.onNodeWithTag("support-center").performScrollToNode(hasText("Исправили сервер. Переподключите VPN"))
        compose.onNodeWithText("Исправили сервер. Переподключите VPN").assertIsDisplayed()
        compose.onNodeWithTag("support-send").assertDoesNotExist()
        compose.onAllNodes(hasText("diagnostic_json", substring = true)).assertCountEquals(0)
    }

    @Test fun offlineNotificationInboxStartsEmptyWithoutSecretFields() {
        compose.setContent {
            QuantumVpnTheme {
                NotificationInboxScreen(onBack = {}, networkEnabled = false, initialEntries = emptyList())
            }
        }
        compose.onNodeWithTag("notification-inbox").assertExists()
        compose.onNodeWithText("Новых уведомлений пока нет.").assertExists()
        compose.onAllNodes(hasText("Токен", substring = true)).assertCountEquals(0)
        compose.onAllNodes(hasText("Пароль", substring = true)).assertCountEquals(0)
    }

    @Test fun offlineInboxKeepsReleaseMaintenanceRecoveryAndSupportTogether() {
        var supportOpened = 0
        val entries = listOf(
            InboxEntry("fixture-release", "release", "Обновление готово", "Новая версия приложения", 1_700_000_004),
            InboxEntry("fixture-maintenance", "maintenance", "Технические работы", "Проводим обслуживание", 1_700_000_003),
            InboxEntry("fixture-recovery", "recovery", "Сервис восстановлен", "Можно снова подключаться", 1_700_000_002),
            InboxEntry("fixture-support", "support_reply", "Ответ поддержки", "Исправили соединение", 1_700_000_001),
        )
        compose.setContent {
            QuantumVpnTheme {
                NotificationInboxScreen(onBack = {}, onOpenSupport = { supportOpened++ },
                    networkEnabled = false, initialEntries = entries)
            }
        }
        for (kind in listOf("release", "maintenance", "recovery", "support_reply")) {
            compose.onNodeWithTag("notification-inbox").performScrollToNode(hasTestTag("inbox-$kind"))
            compose.onNodeWithTag("inbox-$kind").assertExists()
        }
        compose.onNodeWithTag("notification-inbox").performScrollToNode(hasText("Открыть поддержку"))
        compose.onNodeWithText("Открыть поддержку").performClick()
        compose.runOnIdle { check(supportOpened == 1) }
    }
}
