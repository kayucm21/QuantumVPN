package com.quantumvpn.networkbootstrap

/** Stable support-facing codes. Messages may improve; codes must keep their meaning. */
enum class BootstrapFailureCode(
    val value: String,
    val userMessage: String,
) {
    NetworkUnavailable(
        "NET-101",
        "Android не предоставил доступную физическую сеть.",
    ),
    NetworkChanged(
        "NET-102",
        "Физическая сеть изменилась во время подготовки подключения.",
    ),
    DnsTimeout(
        "DNS-101",
        "Системный DNS не ответил вовремя. Дождитесь стабильной сети и повторите подключение.",
    ),
    DnsNameNotFound(
        "DNS-102",
        "Системный DNS не нашёл адрес VPN-сервера.",
    ),
    DnsRefused(
        "DNS-103",
        "Системный или Private DNS отклонил запрос адреса VPN-сервера.",
    ),
    DnsEmptyAnswer(
        "DNS-104",
        "Системный DNS вернул пустой адрес VPN-сервера.",
    ),
    DnsSystem(
        "DNS-105",
        "Android не смог выполнить DNS-запрос для VPN-сервера.",
    ),
    DnsResponse(
        "DNS-106",
        "DNS-сервер вернул ошибку при поиске VPN-сервера.",
    ),
}

interface CodedFailure {
    val failureCode: String
    val userMessage: String
    val technicalDetail: String?
}

class BootstrapFailureException(
    val reason: BootstrapFailureCode,
    override val technicalDetail: String? = null,
    cause: Throwable? = null,
) : Exception(reason.userMessage, cause), CodedFailure {
    override val failureCode: String = reason.value
    override val userMessage: String = reason.userMessage
}

object DnsResponseClassifier {
    const val RCODE_SUCCESS = 0
    const val RCODE_SERVER_FAILURE = 2
    const val RCODE_NAME_ERROR = 3
    const val RCODE_REFUSED = 5

    fun classify(rcode: Int, answerCount: Int): BootstrapFailureCode? = when {
        rcode == RCODE_SUCCESS && answerCount > 0 -> null
        rcode == RCODE_SUCCESS -> BootstrapFailureCode.DnsEmptyAnswer
        rcode == RCODE_NAME_ERROR -> BootstrapFailureCode.DnsNameNotFound
        rcode == RCODE_REFUSED -> BootstrapFailureCode.DnsRefused
        else -> BootstrapFailureCode.DnsResponse
    }
}

enum class NetworkTransitionDecision {
    Accept,
    Retry,
    Fail,
}

object NetworkTransitionPolicy {
    fun <T> decide(
        startedKey: T,
        currentKey: T,
        attempt: Int,
        maxNetworkChanges: Int,
    ): NetworkTransitionDecision = when {
        startedKey == currentKey -> NetworkTransitionDecision.Accept
        attempt < maxNetworkChanges -> NetworkTransitionDecision.Retry
        else -> NetworkTransitionDecision.Fail
    }
}
