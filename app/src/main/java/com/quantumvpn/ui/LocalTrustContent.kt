package com.quantumvpn.ui

/**
 * Local threat-model summary for Settings (no network, no claims beyond local client).
 */
object LocalThreatModel {
    val paragraphs: List<String> = listOf(
        "QuantumVPN — локальный клиент: профили и ключи хранятся на устройстве (Keystore где применимо).",
        "Приложение не требует аккаунта и не отправляет телеметрию по умолчанию.",
        "Угрозы: компрометация устройства, вредоносные подписки, WebRTC/DNS утечки в браузере, Always-on конфликты.",
        "Kill switch и block-localhost снижают риск обхода TUN, но не заменяют обновления ОС и осторожный импорт.",
        "Диагностические отчёты редактируют секреты; делитесь ими только осознанно.",
        "Обновления APK проверяют подпись/совместимость канала; не ставьте APK из неизвестных источников.",
    )
}

object LocalPrivacyPromise {
    val bullets: List<String> = listOf(
        "Не собираем аккаунты и платежи.",
        "Не продаём данные.",
        "Подписки и конфиги остаются на устройстве.",
        "Журнал событий локальный и редактируется.",
        "Обновления — только из настроенного GitHub-канала при проверке пользователем.",
        "Буфер обмена можно очищать после импорта.",
    )
}

object LocalErrorGlossary {
    data class Entry(val code: String, val meaning: String, val action: String)

    val entries: List<Entry> = listOf(
        Entry("VPN-000", "Общая ошибка запуска", "Смотрите журнал и «Почему медленно»; soft/hard reconnect."),
        Entry("permission", "Нет VPN permission", "Подтвердите системный диалог VPN."),
        Entry("dns", "Сбой DNS/DoH", "Смените пресет DNS или отключите Private DNS."),
        Entry("network", "Нет underlying сети", "Проверьте Wi‑Fi/LTE и captive portal."),
        Entry("config", "Невалидный JSON/профиль", "Обновите подписку или переимпортируйте."),
        Entry("scope", "Per-app scope пуст/некорректен", "Добавьте приложения или режим «все»."),
        Entry("core", "Ошибка sing-box core", "Экспортируйте диагностику; hard reconnect."),
        Entry("update", "Несовместимое обновление", "Проверьте подпись и versionCode."),
    )
}

object LocalOemQuirks {
    data class Entry(val oem: String, val tip: String)

    val entries: List<Entry> = listOf(
        Entry("Xiaomi / MIUI / HyperOS", "Автозапуск + без ограничений батареи; отключите «экономию» для QuantumVPN."),
        Entry("Huawei / Honor", "Protected apps / запуск вручную после перезагрузки."),
        Entry("OPPO / ColorOS / Realme", "Автозапуск и фоновая активность в менеджере приложений."),
        Entry("vivo / Funtouch", "High background power consumption → разрешить."),
        Entry("Samsung", "Не усыплять приложение; Always-on VPN в настройках подключений."),
        Entry("Pixel / AOSP", "Обычно достаточно игнора оптимизации батареи."),
        Entry("GrapheneOS / Calyx /e/", "Проверьте Network permission и VPN always-on вручную."),
        Entry("Android TV / Wear / Auto", "Отдельные клиенты не входят в phone APK (см. дорожную карту)."),
    )
}

object LocalAccessibilityStatement {
    val paragraphs: List<String> = listOf(
        "Интерфейс на Material 3 с системными размерами шрифта; доступен режим «крупный текст».",
        "Ключевые кнопки имеют contentDescription; навигация поддерживает системную кнопку «назад».",
        "Reduce motion уменьшает анимации на Home.",
        "Цветовой акцент выбирается в оформлении; OLED-чёрный снижает засветку.",
        "Если нужен TalkBack-сценарий — опишите проблему в issue; мы расширяем a11y точечно.",
    )
}
