"""Bounded, aggregate-only Telegram status and read-only command admission.

No network calls, writes, credential access, model execution, or Telegram side
effects live here. The operator provides independently measured runtime/model
facts. Missing evidence remains unknown instead of being displayed as zero or
as an invented active service. Messages are sent as plain text, not HTML.
"""
from __future__ import annotations

import json
import hashlib
import itertools
import math
import re
import sqlite3
import time


COMMANDS = frozenset({
    "/start", "/status", "/help", "/check_updates", "/get_stable",
    "/get_dev", "/ai_status", "/backups",
})
_COMMAND_DESCRIPTIONS = (
    ("status", "Статус VDS, ИИ, APK и доставки"),
    ("ai_status", "Модель, анализы и сетевые проверки"),
    ("check_updates", "Публичная версия и расписание выпуска"),
    ("get_stable", "Скачать опубликованный Android APK"),
    ("get_dev", "Проверить наличие отдельного dev APK"),
    ("backups", "Состояние и доставка резервных копий"),
    ("help", "Список доступных команд"),
    ("start", "Открыть помощь бота"),
)
MAX_STATUS_CHARS = 3500
OPERATIONS_KNOWLEDGE_VERSION = "quantum-control-facts-v1"
_SERVICE_STATES = frozenset({"active", "inactive", "failed", "activating", "deactivating"})
_PROXY_PROTOCOLS = {"mtproto": "mtproto_req_pq_multi", "native_tls": "mtproto_fake_tls_req_pq_multi", "web": "web_mtproto_req_pq_multi"}
_MODEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+-]{0,79}\Z")
_VERSION = re.compile(r"[0-9][A-Za-z0-9_.+-]{0,39}\Z")
AI_ERROR_LABELS = {
    "invalid_response": "ответ модели не прошёл проверку формата",
    "truncated_response": "ответ модели обрезан лимитом генерации",
    "busy": "предыдущий анализ ещё выполняется",
    "resources": "анализ отложен из-за нагрузки VDS",
    "too_large": "ответ или входные данные превысили безопасный лимит",
    "unavailable": "локальный анализ не завершён; проверьте службу ИИ",
}
AI_ERROR_REASON_LABELS = {
    "transport": "не удалось получить ответ локального сервера ИИ",
    "request_size": "входные данные превысили безопасный лимит",
    "response_size": "ответ сервера ИИ превысил безопасный лимит",
    "response_json": "сервер ИИ вернул некорректный JSON",
    "response_shape": "структура ответа сервера ИИ не соответствует контракту",
    "output_truncated": "ответ модели обрезан лимитом генерации",
    "finish_reason": "модель не завершила ответ штатно",
    "tool_calls": "модель предложила запрещённый вызов инструмента",
    "content_type": "текст ответа модели отсутствует",
    "content_size": "текст ответа модели превысил безопасный лимит",
    "content_json": "текст модели не является корректным JSON",
    "analysis_shape": "поля отчёта модели не соответствуют схеме",
    "status_value": "модель вернула неизвестный статус",
    "text_type": "поля отчёта модели не являются текстом",
    "text_length": "длина текста отчёта не соответствует схеме",
    "text_controls": "в отчёте модели есть недопустимые управляющие символы",
    "text_encoding": "кодировка отчёта модели некорректна",
    "recommendations_shape": "список рекомендаций не соответствует схеме",
    "recommendation_not_allowed": "модель предложила действие вне разрешённого списка",
}


def _ai_error_label(ai):
    reason = _choice(ai.get("last_error_reason"), AI_ERROR_REASON_LABELS)
    code = _choice(ai.get("last_error_code"), AI_ERROR_LABELS)
    return AI_ERROR_REASON_LABELS[reason] if reason else AI_ERROR_LABELS[code] if code else ""


def _integer(value, minimum=0, maximum=2**63 - 1):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and re.fullmatch(r"-?[0-9]{1,20}", value):
        result = int(value)
    else:
        return None
    return result if minimum <= result <= maximum else None


def _number(value, maximum=100):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return value if math.isfinite(value) and 0 <= value <= maximum else None
    except (OverflowError, ValueError):
        return None


def _flag(value):
    if value is True or value == "1" or type(value) is int and value == 1:
        return True
    if value is False or value == "0" or type(value) is int and value == 0:
        return False
    return None


def _safe_name(value, regex):
    return value if isinstance(value, str) and regex.fullmatch(value) else None


def _choice(value, choices):
    return value if isinstance(value, str) and value in choices else None


def _operations_status(value, engine, now):
    value = value if isinstance(value, dict) else {}
    return {
        "monitor_interval_seconds": _integer(value.get("monitor_interval_seconds"), minimum=30, maximum=3600),
        "confirm_samples": _integer(value.get("confirm_samples"), minimum=1, maximum=10),
        "ai_interval_seconds": _integer(value.get("ai_interval_seconds"), minimum=600 if engine == "llama.cpp" else 300, maximum=86400),
        "ai_isolation_verified": _flag(value.get("ai_isolation_verified")),
        "knowledge_version": OPERATIONS_KNOWLEDGE_VERSION,
        "backup_verified": _flag(value.get("backup_verified")),
        "backup_checked_at": _integer(value.get("backup_checked_at"), minimum=1, maximum=now),
        "backup_db_count": _integer(value.get("backup_db_count"), maximum=2),
        "backup_missing_count": _integer(value.get("backup_missing_count"), maximum=6),
    }


def _proxy_status(value, now):
    value = value if isinstance(value, dict) else {}
    result = {}
    for name, protocol in _PROXY_PROTOCOLS.items():
        item = value.get(name) if isinstance(value.get(name), dict) else {}
        checked = _integer(item.get("checked_at"), minimum=1, maximum=now)
        method = _choice(item.get("protocol"), {protocol})
        result[name] = {
            "service": _choice(item.get("service"), _SERVICE_STATES),
            "checked_at": checked,
            "stage": _choice(item.get("stage"), {"not_checked", "tcp", "tls", "bridge", "telegram", "failed"}),
            "protocol": method,
            # A running process or TCP connection is not an MTProto nonce proof.
            "ready": (True if item.get("ready") is True and item.get("stage") == "telegram" else
                      False if item.get("ready") is False and item.get("stage") in {"tcp", "tls", "bridge", "telegram", "failed"} else None) if checked and method else None,
            "isolation_verified": _flag(item.get("isolation_verified")),
        }
    return result


def _maintenance(settings, now):
    manual = _flag(settings.get("maintenance"))
    scheduled = _flag(settings.get("maintenance_schedule_enabled"))
    start = _integer(settings.get("maintenance_start"))
    end = _integer(settings.get("maintenance_end"))
    if manual is True:
        return True
    if scheduled is True:
        if start is None or end is None or not 0 < start < end:
            return None
        if start <= now < end:
            return True
    return False if manual is False else None


def bot_commands():
    """Telegram setMyCommands payload; caller must apply private-chat scope."""
    return [{"command": command, "description": description} for command, description in _COMMAND_DESCRIPTIONS]


def command_help():
    """Static bounded help for the actual read-only bot, not the example bot."""
    lines = ["💡 Команды Quantum Control Bot (только просмотр)"]
    lines.extend(f"/{command} — {description}" for command, description in _COMMAND_DESCRIPTIONS if command != "start")
    lines.extend([
        "", "Бот работает на VDS: ПК и Codex не нужны.",
        "Запланированный APK недоступен до времени выпуска.",
        "ИИ-советник не исполняет произвольные команды.",
        "Резервные копии и настройки меняются в панели, не командами бота.",
        "Команды доступны только в настроенном личном чате администратора.",
    ])
    return "\n".join(lines)


def _scalar(db, query, params=()):
    try:
        row = db.execute(query, params).fetchone()
        return row[0] if row else None
    except sqlite3.Error:
        # Upgrades and an unavailable metrics table must not invent counters.
        return None


def _latest_delivery(db):
    try:
        rows = db.execute(
            "select ts,detail from audit where action in ('hourly_backup','backup_now') "
            "order by ts desc limit 1"
        ).fetchall()
    except sqlite3.Error:
        return None, None
    if not rows:
        return None, None
    stamp, detail = rows[0]
    try:
        if not isinstance(detail, str) or len(detail) > 4096:
            return _integer(stamp), None
        body = json.loads(detail)
        ok = body.get("ok") if isinstance(body, dict) else None
        return _integer(stamp), ok if type(ok) is bool else None
    except (ValueError, TypeError):
        return _integer(stamp), None


def collect_status(db, settings, runtime=None, local_model=None, now=None):
    """Read aggregate SQLite facts plus allowlisted observed runtime values.

    Runtime keys: cpu_percent, memory_percent, disk_percent, memory_total_bytes,
    services (operator/rospanel/xray/ollama systemd states), backup (exists/ts/
    size/encrypted), polling, webhook, active_ai_requests, system_instruction,
    operations (bounded cadence/aggregate backup verification), proxies (three
    fixed proxy kinds, service/probe/isolation evidence; never connection links).
    Local model
    keys: ready (installed catalogue), loaded (resident), memory_bytes. Neither
    dictionary is echoed; unknown/raw error fields are deliberately discarded.
    """
    settings = settings if isinstance(settings, dict) else {}
    runtime = runtime if isinstance(runtime, dict) else {}
    local_model = local_model if isinstance(local_model, dict) else {}
    now = _integer(int(time.time()) if now is None else now) or 0
    cutoff = now - 30 * 86400
    count = _integer(_scalar(db, "select count(*) from ai_observations where ts>=? and ts<=?", (cutoff, now)))
    success = _integer(_scalar(db, "select count(*) from ai_observations where ts>=? and ts<=? and status='готов'", (cutoff, now)))
    health_count = _integer(_scalar(db, "select count(*) from server_health where ts>=? and ts<=?", (now - 86400, now)))
    health_ok = _integer(_scalar(db, "select count(*) from server_health where ts>=? and ts<=? and ok=1", (now - 86400, now)))
    latency = _number(_scalar(db, "select avg(latency_ms) from server_health where ts>=? and ts<=? and ok=1 and latency_ms>0", (now - 86400, now)), maximum=600000)
    services = runtime.get("services") if isinstance(runtime.get("services"), dict) else {}
    guard = runtime.get("network_guard") if isinstance(runtime.get("network_guard"), dict) else {}
    automation = runtime.get("automation") if isinstance(runtime.get("automation"), dict) else {}
    coverage = guard.get("coverage") if isinstance(guard.get("coverage"), dict) else {}
    backup = runtime.get("backup") if isinstance(runtime.get("backup"), dict) else {}
    delivered_at, delivered_ok = _latest_delivery(db)
    code = _integer(settings.get("app_version_code"))
    funnel = {}
    for stage in ("notification_received", "download_complete", "install_handoff", "app_started"):
        funnel[stage] = _integer(_scalar(
            db, "select count(distinct device) from community_delivery where version_code=? "
            "and stage=? and ts>=? and ts<=?", (code, stage, now - 7 * 86400, now)
        )) if code is not None else None
    return {
        "generated_at": now,
        "ai": {
            "enabled": _flag(settings.get("ai_advisor_enabled")),
            "model": _safe_name(settings.get("ai_model"), _MODEL_NAME),
            "provider": "gemini" if local_model.get("provider") == "gemini" else "qwen",
            "engine": _choice(local_model.get("engine"), {"ollama", "llama.cpp"}),
            "key_configured": _flag(local_model.get("key_configured")),
            "catalogue_available": _flag(local_model.get("ready")),
            "loaded": _flag(local_model.get("loaded")),
            "memory_bytes": _integer(local_model.get("memory_bytes")),
            "active_requests": _integer(runtime.get("active_ai_requests"), maximum=10000),
            "last_run": _integer(settings.get("ai_last_run")),
            "last_status": _choice(settings.get("ai_last_status"), {"готов", "ожидание", "выключен", "ошибка", "ожидание модели"}),
            "last_error_code": _choice(settings.get("ai_last_error"), AI_ERROR_LABELS),
            "last_error_reason": _choice(settings.get("ai_last_error_reason"), AI_ERROR_REASON_LABELS),
            "observations_30d": count,
            "succeeded_30d": success,
            "success_percent": round(success * 100 / count, 1) if count and success is not None else None,
            "instruction_present": _flag(runtime.get("system_instruction")),
        },
        "server": {
            "cpu_percent": _number(runtime.get("cpu_percent")),
            "memory_percent": _number(runtime.get("memory_percent")),
            "disk_percent": _number(runtime.get("disk_percent")),
            "memory_total_bytes": _integer(runtime.get("memory_total_bytes")),
            "services": {name: _choice(services.get(name), {"active", "inactive", "failed", "activating", "deactivating"}) for name in ("operator", "rospanel", "xray", "ollama", "llama_cpp")},
            "health_checks_24h": health_count,
            "health_ok_percent_24h": round(health_ok * 100 / health_count, 1) if health_count and health_ok is not None else None,
            "mean_latency_ms": round(latency, 1) if latency is not None else None,
            "network_status": _choice(guard.get("status"), {"healthy", "degraded", "insufficient_data"}),
            "coverage": {stage: _integer(coverage.get(stage), maximum=24) for stage in ("dns", "tcp", "tls")},
        },
        "release": {
            "version": _safe_name(settings.get("app_version"), _VERSION),
            "version_code": code,
            "rollout_percent": _integer(settings.get("rollout_percent"), maximum=100),
            "notifications_enabled": _flag(settings.get("update_notifications_enabled")),
            "maintenance": _maintenance(settings, now),
            "download_enabled": _flag(settings.get("public_download_enabled")),
            "scheduled_version": _safe_name(settings.get("scheduled_app_version"), _VERSION),
            "scheduled_at": _integer(settings.get("release_publish_at")),
            "scheduled_enabled": _flag(settings.get("release_schedule_enabled")),
            "protocols_enabled": _integer(_scalar(db, "select count(*) from protocols where enabled=1")),
            "protocols_total": _integer(_scalar(db, "select count(*) from protocols")),
        },
        "delivery": {"window_days": 7, **funnel},
        "backup": {
            "exists": _flag(backup.get("exists")),
            "encrypted": _flag(backup.get("encrypted")),
            "ts": _integer(backup.get("ts")),
            "size_bytes": _integer(backup.get("size")),
            "hourly_enabled": _flag(settings.get("telegram_backups_enabled")),
            "last_delivery_at": delivered_at,
            "last_delivery_ok": delivered_ok,
        },
        "support": {"open_threads": _integer(_scalar(db, "select count(*) from community_threads where state='open'"))},
        "bot": {
            "polling": _flag(runtime.get("polling")),
            "webhook": _flag(runtime.get("webhook")),
            "alerts_enabled": _flag(settings.get("telegram_alerts_enabled")),
        },
        "automation": {
            "enabled": _flag(automation.get("enabled")),
            "mode": _choice(automation.get("mode"), {"observe", "bounded"}),
            "actions_24h": _integer(automation.get("actions_24h")),
            "last_action": _choice(automation.get("last_action"), {"recommendation_changed", "node_quarantined", "node_restored", "probe_failed", "rollback"}),
            "last_action_at": _integer(automation.get("last_action_at")),
            "last_result": _choice(automation.get("last_result"), {"verified", "verifying", "rolled_back", "failed", "blocked"}),
        },
        "operations": _operations_status(runtime.get("operations"), local_model.get("engine"), now),
        "proxies": _proxy_status(runtime.get("proxies"), now),
    }


def _count(value):
    value = _integer(value)
    return str(value) if value is not None else "нет данных"


def _state(value):
    return "✅ включено" if value is True else "⏸ выключено" if value is False else "нет данных"


def _delivery(value):
    return "✅ успешно" if value is True else "❌ ошибка отправки" if value is False else "нет данных"


def _encryption(value):
    return "✅ подтверждено" if value is True else "❌ не подтверждено" if value is False else "нет данных"


def _percent(value):
    value = _number(value)
    return f"{value:g}%" if value is not None else "нет данных"


def _bar(value):
    value = _number(value)
    if value is None:
        return "нет данных"
    filled = round(value / 10)
    return "▰" * filled + "▱" * (10 - filled) + f" {_percent(value)}"


def _stamp(value):
    value = _integer(value, maximum=253402290000)
    if not value:
        return "нет данных"
    try:
        return time.strftime("%d.%m.%Y %H:%M МСК", time.gmtime(value + 10800))
    except (OverflowError, OSError, ValueError):
        return "нет данных"


def _bytes(value):
    value = _integer(value)
    return f"{value / 1048576:.1f} МБ" if value is not None else "нет данных"


def _model_runtime(ai):
    if ai.get("provider") == "gemini":
        return "официальный Google API"
    engine = _choice(ai.get("engine"), {"ollama", "llama.cpp"})
    return f"локально · {engine}" if engine else "локально, не облачный API"


def format_status(snapshot):
    """Render allowlisted, evidence-labelled fields only; under 3,500 chars."""
    snapshot = snapshot if isinstance(snapshot, dict) else {}
    def section(name):
        return snapshot.get(name) if isinstance(snapshot.get(name), dict) else {}
    ai, server, release = section("ai"), section("server"), section("release")
    automation = section("automation")
    generated = _integer(snapshot.get("generated_at")) or 0
    operations = _operations_status(section("operations"), ai.get("engine"), generated)
    proxies = _proxy_status(section("proxies"), generated)
    delivery, backup, bot = section("delivery"), section("backup"), section("bot")
    model = _safe_name(ai.get("model"), _MODEL_NAME) or "нет данных"
    version = _safe_name(release.get("version"), _VERSION) or "нет данных"
    last_status = _choice(ai.get("last_status"), {"готов", "ожидание", "выключен", "ошибка", "ожидание модели"}) or "нет данных"
    loaded = ai.get("loaded")
    memory = _bytes(ai.get("memory_bytes"))
    total = _integer(server.get("memory_total_bytes"))
    resident = _integer(ai.get("memory_bytes"))
    share = f" · {resident * 100 / total:.1f}% RAM сервера" if total and resident is not None and resident <= total else ""
    service_names = {"operator": "Доп. панель", "rospanel": "Основная панель", "xray": "VPN Xray"}
    engine = _choice(ai.get("engine"), {"ollama", "llama.cpp"})
    if engine == "llama.cpp":
        service_names["llama_cpp"] = "llama.cpp"
    elif ai.get("provider") != "gemini":
        service_names["ollama"] = "Ollama"
    service_states = {"active": "✅ работает", "inactive": "⏸ остановлена", "failed": "❌ ошибка", "activating": "⏳ запускается", "deactivating": "⏳ останавливается"}
    services = server.get("services") if isinstance(server.get("services"), dict) else {}
    lines = [
        "🤖 Статус Quantum Control Bot",
        f"Срез: {_stamp(snapshot.get('generated_at'))}", "",
        "🧠 ИИ-советник",
        f"• Советник: {_state(ai.get('enabled'))}",
        f"• Модель: {model} · {_model_runtime(ai)}",
        f"• {'Серверный API-ключ: ' + _state(ai.get('key_configured')) if ai.get('provider') == 'gemini' else 'Модель установлена: ' + _state(ai.get('catalogue_available'))}",
        f"• {'Облачная модель; RAM VDS не используется для весов' if ai.get('provider') == 'gemini' else 'В RAM: ' + _state(loaded) + ' · ' + (memory + share if loaded is True else 'модель выгружена' if loaded is False else 'нет данных')}",
        f"• Активных анализов: {_count(ai.get('active_requests'))}",
        f"• Анализов за 30 дней: {_count(ai.get('observations_30d'))}",
        f"• Успешных: {_count(ai.get('succeeded_30d'))} · {_percent(ai.get('success_percent'))}",
        f"• Последний анализ: {_stamp(ai.get('last_run'))} · {last_status}",
        f"• Системная инструкция: {_state(ai.get('instruction_present'))}",
        "• Диалоги не ведутся; " + ("ключ не выводится в статус" if ai.get('provider') == 'gemini' else "API-ключи не используются"),
        "• ИИ не исполняет произвольные команды",
        "• CPU/RAM — ресурсы VDS, не процент прогресса ИИ",
    ]
    error_label = _ai_error_label(ai)
    if last_status == "ошибка" and error_label:
        lines.append("• Причина анализа: " + error_label)
        lines.append("• Ошибка ИИ не доказывает сбой VPN; монитор нод работает отдельно")
    if automation.get("enabled") is not None:
        modes = {"observe": "наблюдение", "bounded": "действия по проверенным правилам"}
        lines.extend([
            f"• Автоуправление нодами: {_state(automation.get('enabled'))} · {modes.get(_choice(automation.get('mode'), modes), 'режим неизвестен')}",
            f"• Действий за 24 ч: {_count(automation.get('actions_24h'))}",
        ])
        last_action = _choice(automation.get("last_action"), {"recommendation_changed", "node_quarantined", "node_restored", "probe_failed", "rollback"})
        if last_action:
            labels = {"recommendation_changed": "обновлена рекомендация", "node_quarantined": "нода временно исключена", "node_restored": "нода возвращена", "probe_failed": "проверка не пройдена", "rollback": "откат"}
            results = {"verified": "проверено", "verifying": "ожидаются контрольные проверки", "rolled_back": "откат выполнен", "failed": "ошибка", "blocked": "действие не применено"}
            lines.append(f"• Последнее действие: {labels[last_action]} · {results.get(_choice(automation.get('last_result'), results), 'результат неизвестен')}")
    if any(operations[name] is not None for name in ("monitor_interval_seconds", "confirm_samples", "ai_interval_seconds")):
        lines.extend([
            f"• Монитор: каждые {_count(operations['monitor_interval_seconds'])} с · подтверждение {_count(operations['confirm_samples'])} замерами",
            f"• Анализ модели: не чаще {_count(operations['ai_interval_seconds'])} с; монитор работает отдельно",
            "• Правила отчёта: " + OPERATIONS_KNOWLEDGE_VERSION,
        ])
        if ai.get("engine") == "llama.cpp":
            isolated = operations["ai_isolation_verified"]
            lines.append("• Изоляция процесса ИИ: " + ("✅ непривилегированный, seccomp, без capabilities" if isolated is True else
                         "❌ проверка не пройдена" if isolated is False else "нет данных"))
    lines.extend([
        "", "📊 Ресурсы VDS (реальный замер)",
        f"• CPU: {_bar(server.get('cpu_percent'))}",
        f"• RAM: {_bar(server.get('memory_percent'))}",
        f"• Диск: {_bar(server.get('disk_percent'))}",
    ])
    lines.extend(f"• {label}: {service_states.get(_choice(services.get(key), service_states), 'нет данных')}" for key, label in service_names.items())
    lines.extend([
        f"• Успешных проверок за 24 ч: {_percent(server.get('health_ok_percent_24h'))} ({_count(server.get('health_checks_24h'))})",
        f"• Средняя задержка проверок: {_count(round(server['mean_latency_ms'])) if _number(server.get('mean_latency_ms'), 600000) is not None else 'нет данных'} мс",
        "• Это проверки VDS, не пинг пользователей", "",
        f"• Сетевой монитор: { {'healthy': 'стабильные серверные проверки', 'degraded': 'повторное ухудшение', 'insufficient_data': 'недостаточно данных'}.get(_choice(server.get('network_status'), {'healthy', 'degraded', 'insufficient_data'}), 'нет данных')}",
        "• Причина ТСПУ не доказана; скорость VPN не измеряется", "",
        "• Проверки ограничены по времени и нагрузке; замер не равен прогнозу", "",
    ])
    if any(any(item[field] is not None for field in ("service", "checked_at", "isolation_verified")) for item in proxies.values()):
        lines.append("🔌 Telegram-прокси (последний серверный тест)")
        stages = {"not_checked": "не проверялся", "tcp": "TCP", "tls": "TLS", "bridge": "HTTPS-мост", "telegram": "ответ Telegram", "failed": "не завершён"}
        for name, label in (("mtproto", "MTProto · 3443"), ("native_tls", "Native TLS · 5443"), ("web", "WEB Proxy · 443")):
            item = proxies[name]
            ready = "✅ nonce подтверждён" if item["ready"] is True else "❌ nonce не подтверждён" if item["ready"] is False else "результат неизвестен"
            isolation = "подтверждена" if item["isolation_verified"] is True else "не подтверждена" if item["isolation_verified"] is False else "нет данных"
            lines.extend([
                f"• {label}: {service_states.get(item['service'], 'нет данных')} · {ready}",
                f"  Этап: {stages.get(item['stage'], 'нет данных')} · {_stamp(item['checked_at'])}; изоляция: {isolation}",
            ])
        lines.extend(["• Не тест входа в аккаунт и не доступность с телефона без VPN", ""])
    lines.extend([
        "📦 APK и выпуск (хранилище VDS)",
        f"• Публичная версия: {version} · код {_count(release.get('version_code'))}",
        f"• Охват: {_percent(release.get('rollout_percent'))}",
        f"• Оповещения: {_state(release.get('notifications_enabled'))}",
        f"• Техработы: {_state(release.get('maintenance'))}",
        f"• Скачивание: {_state(False if release.get('maintenance') is True else release.get('download_enabled'))}",
        f"• Протоколов разрешено: {_count(release.get('protocols_enabled'))}/{_count(release.get('protocols_total'))}",
    ])
    if release.get("scheduled_enabled") is True:
        scheduled = _safe_name(release.get("scheduled_version"), _VERSION) or "нет данных"
        lines.append(f"• Запланировано: {scheduled} · {_stamp(release.get('scheduled_at'))}")
    else:
        lines.append("• Запланированного выпуска нет" if release.get("scheduled_enabled") is False else "• Расписание: нет данных")
    lines.extend([
        "• GitHub, MTProto и сторонние каналы не используются", "",
        "📢 Оповещения и доставка APK",
        f"• Приём команд Telegram: {_state(bot.get('polling'))}",
        f"• Telegram webhook: {_state(bot.get('webhook'))}",
        f"• Серверные алерты: {_state(bot.get('alerts_enabled'))}",
        f"• За 7 дней, текущая версия: уведомление {_count(delivery.get('notification_received'))} · скачано {_count(delivery.get('download_complete'))}",
        f"• Установщик открыт: {_count(delivery.get('install_handoff'))} · запуск APK: {_count(delivery.get('app_started'))}",
        "• Самоотчёты клиентов; открытие установщика ≠ установка", "",
        "🔐 Резервные копии",
        f"• Копия на VDS: {_state(backup.get('exists'))} · {_bytes(backup.get('size_bytes'))}",
        f"• Шифрование архива: {_encryption(backup.get('encrypted'))}",
        f"• Последняя копия: {_stamp(backup.get('ts'))}",
        f"• Часовая отправка: {_state(backup.get('hourly_enabled'))}",
        f"• Последняя доставка: {_stamp(backup.get('last_delivery_at'))} · {_delivery(backup.get('last_delivery_ok'))}",
    ])
    if any(operations[name] is not None for name in ("backup_verified", "backup_checked_at", "backup_db_count", "backup_missing_count")):
        verified = "✅ пройдена" if operations['backup_verified'] is True else "❌ не пройдена" if operations['backup_verified'] is False else "нет данных"
        lines.extend([
            f"• Проверка восстановления: {verified} · {_stamp(operations['backup_checked_at'])}",
            f"• Баз проверено: {_count(operations['backup_db_count'])} · компонентов отсутствует: {_count(operations['backup_missing_count'])}",
        ])
    lines.extend([
        f"• Открытых обращений: {_count(section('support').get('open_threads'))}", "",
        "💡 Команды (только просмотр)",
        "/status — полный статус · /ai_status — ИИ",
        "/check_updates — выпуск · /get_stable — APK",
        "/get_dev — отдельный тестовый выпуск, если доступен",
        "/backups — состояние копий · /help — помощь",
    ])
    text = "\n".join(lines)
    # Drop Unicode controls as well as C0/C1 so supplied labels cannot hide text.
    text = "".join(char for char in text if char == "\n" or char >= " " and not ("\x7f" <= char <= "\x9f") and char not in "\u200b\u200c\u200d\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\ufeff")
    if len(text) <= MAX_STATUS_CHARS:
        return text
    # Keep the actual command footer intact even with maximal valid names and
    # aggregate counters. Prefer dropping explanatory repetitions to cutting
    # a backup result or a command in the middle of its sentence.
    optional = (
        "• CPU/RAM — ресурсы VDS, не процент прогресса ИИ\n",
        "• Проверки ограничены по времени и нагрузке; замер не равен прогнозу\n",
        "• GitHub, MTProto и сторонние каналы не используются\n",
        "• Диалоги не ведутся; API-ключи не используются\n",
        "• Диалоги не ведутся; ключ не выводится в статус\n",
    )
    for line in optional:
        text = text.replace(line, "", 1)
        if len(text) <= MAX_STATUS_CHARS:
            return text
    marker = "💡 Команды (только просмотр)"
    body, footer = text.split(marker, 1)
    footer = marker + footer
    limit = MAX_STATUS_CHARS - len(footer) - 2
    body = body[:limit]
    if "\n" in body:
        body = body.rsplit("\n", 1)[0]
    return body.rstrip() + "\n\n" + footer


def format_backup_caption(snapshot, kind="hourly"):
    """Short factual archive caption; full status follows it.

    Telegram document captions are shorter than messages. Keep this below 900
    characters, include the report timestamp, and avoid model-generated prose.
    """
    snapshot = snapshot if isinstance(snapshot, dict) else {}
    server = snapshot.get("server") if isinstance(snapshot.get("server"), dict) else {}
    ai = snapshot.get("ai") if isinstance(snapshot.get("ai"), dict) else {}
    backup = snapshot.get("backup") if isinstance(snapshot.get("backup"), dict) else {}
    release = snapshot.get("release") if isinstance(snapshot.get("release"), dict) else {}
    title = "часовая" if kind == "hourly" else "ручная"
    status = {"healthy": "стабильные проверки", "degraded": "повторное ухудшение", "insufficient_data": "накапливаются замеры"}.get(_choice(server.get("network_status"), {"healthy", "degraded", "insufficient_data"}), "нет данных")
    model = _safe_name(ai.get("model"), _MODEL_NAME) or "нет данных"
    version = _safe_name(release.get("version"), _VERSION) or "нет данных"
    lines = [
        f"🔐 Quantum Control · {title} резервная копия",
        f"Срез: {_stamp(snapshot.get('generated_at'))}",
        f"📦 Архив: {_bytes(backup.get('size_bytes'))} · шифрование: {_encryption(backup.get('encrypted'))}",
        f"🧠 {model} · {_model_runtime(ai)}",
        f"📊 CPU {_percent(server.get('cpu_percent'))} · RAM {_percent(server.get('memory_percent'))} · диск {_percent(server.get('disk_percent'))}",
        f"🌐 Сеть: {status}",
        f"📱 Публичный APK: {version}",
        "Полный отчёт — в ответе к этому файлу.",
        "Формат и ключ архива не выводятся в сообщении.",
    ]
    return "\n".join(lines)[:900]


_ISSUE_LABELS = {
    "cpu_percent": "CPU", "memory_percent": "RAM", "disk_percent": "Диск",
    "service_operator": "Дополнительная панель", "service_rospanel": "Основная панель",
    "service_xray": "VPN Xray", "service_ollama": "Локальный ИИ · Ollama",
    "service_llama_cpp": "Локальный ИИ · llama.cpp", "network_degraded": "Серверные сетевые проверки",
    "analysis_error": "Анализ ИИ", "backup_stale": "Свежая резервная копия",
    "backup_delivery_failed": "Доставка копии в Telegram",
    "proxy_mtproto": "MTProto · 3443", "proxy_native_tls": "Native TLS · 5443",
    "proxy_web": "WEB Proxy · 443",
}
_GROUPS = (
    ("📊 Ресурсы VDS", ("cpu_percent", "memory_percent", "disk_percent"),
     "Проверьте процессы и место в панели. Не удаляйте базы, ключи и рабочие APK."),
    ("🌐 Службы", ("service_operator", "service_rospanel", "service_xray"),
     "Проверьте журнал указанных служб. Не перезапускайте активные VPN-сессии без проверки причины."),
    ("📡 Сеть", ("network_degraded",),
     "Откройте «Сеть → Ноды» и сравните серии DNS/TCP/TLS с резервным путём."),
    ("🧠 ИИ", ("service_ollama", "service_llama_cpp", "analysis_error"),
     "Проверьте службу и последний анализ ИИ. VPN и монитор нод проверяются отдельно."),
    ("🔐 Резерв", ("backup_stale", "backup_delivery_failed"),
     "Откройте «Резервные копии», проверьте архив и доставку; сохраните последнюю рабочую копию."),
    ("📨 Telegram", ("proxy_mtproto", "proxy_native_tls", "proxy_web"),
     "Откройте «Сеть → Telegram», проверьте протокол и затем путь с телефона без VPN. Не публикуйте ключи прокси."),
)
MAX_ALERT_CHARS = 3000
FACT_ISSUE_CODES = tuple(_ISSUE_LABELS)


def _fact_conditions(snapshot):
    """Per-issue measured bad/healthy/unknown; AI prose never supplies evidence."""
    snapshot = snapshot if isinstance(snapshot, dict) else {}
    def section(name):
        return snapshot.get(name) if isinstance(snapshot.get(name), dict) else {}
    server, ai, backup = section("server"), section("ai"), section("backup")
    generated = _integer(snapshot.get("generated_at"))
    conditions = {key: None for key in _ISSUE_LABELS}
    labels = {}
    for name, label, threshold in (("cpu_percent", "CPU", 90), ("memory_percent", "RAM", 90), ("disk_percent", "диск", 85)):
        value = _number(server.get(name))
        if value is not None:
            conditions[name] = value >= threshold
            labels[name] = f"{label}: {_percent(value)} · порог {threshold}%"
    services = server.get("services") if isinstance(server.get("services"), dict) else {}
    service_labels = {"operator": "Дополнительная панель", "rospanel": "Основная панель", "xray": "VPN Xray"}
    if ai.get("enabled") is True and ai.get("provider") != "gemini":
        service_labels["llama_cpp" if ai.get("engine") == "llama.cpp" else "ollama"] = "Локальный ИИ"
    for key, label in service_labels.items():
        state = _choice(services.get(key), {"active", "inactive", "failed", "activating", "deactivating"})
        code = "service_" + key
        if state in {"inactive", "failed"}:
            conditions[code] = True
            labels[code] = label + (": служба остановлена" if state == "inactive" else ": ошибка службы")
        elif state == "active":
            conditions[code] = False
    network = _choice(server.get("network_status"), {"healthy", "degraded", "insufficient_data"})
    if network in {"healthy", "degraded"}:
        conditions["network_degraded"] = network == "degraded"
        labels["network_degraded"] = "Сеть: подтверждено повторное ухудшение серверных проверок"
    if ai.get("enabled") is True:
        if ai.get("last_status") == "ошибка":
            conditions["analysis_error"] = True
            labels["analysis_error"] = "ИИ: " + (_ai_error_label(ai) or "последний анализ завершился ошибкой")
        elif ai.get("last_status") == "готов":
            conditions["analysis_error"] = False
    if backup.get("hourly_enabled") is True:
        stamp = _integer(backup.get("ts"))
        if backup.get("exists") is False:
            conditions["backup_stale"] = True
        elif backup.get("exists") is True and generated and stamp and 0 <= generated - stamp:
            conditions["backup_stale"] = generated - stamp > 2 * 3600
        labels["backup_stale"] = "Резервная копия: нет свежего архива за последние два часа"
        if backup.get("last_delivery_ok") is False:
            conditions["backup_delivery_failed"] = True
        elif backup.get("last_delivery_ok") is True:
            conditions["backup_delivery_failed"] = False
        labels["backup_delivery_failed"] = "Резервная копия: последняя отправка в Telegram не удалась"
    proxies = _proxy_status(section("proxies"), generated or 0)
    for name, item in proxies.items():
        key = "proxy_" + name
        if item["service"] in {"inactive", "failed"}:
            conditions[key] = True
            labels[key] = _ISSUE_LABELS[key] + (": служба остановлена" if item["service"] == "inactive" else ": ошибка службы")
        elif item["service"] == "active" and item["checked_at"] and generated is not None and 0 <= generated - item["checked_at"] <= 900:
            if item["ready"] is not None:
                conditions[key] = not item["ready"]
                labels[key] = _ISSUE_LABELS[key] + ": свежий тест протокола не подтвердил nonce Telegram"
    return conditions, labels


def _fact_issues(snapshot):
    conditions, labels = _fact_conditions(snapshot)
    return [(key, labels[key]) for key in _ISSUE_LABELS if conditions[key] is True]


def fact_observation(snapshot):
    """Typed measurement states for the caller's bounded confirmation counters.

    No delivery state or prose is returned. Unknown is not a healthy sample.
    Measurements here are facts, not an AI judgement or client-speed forecast.
    """
    conditions, _ = _fact_conditions(snapshot)
    return {"schema": 1, "conditions": {
        code: "bad" if state is True else "healthy" if state is False else "unknown"
        for code, state in conditions.items()
    }}


def _confirmed_keys(value):
    if value is None:
        return None
    if (not isinstance(value, (list, tuple, set, frozenset)) or len(value) > len(FACT_ISSUE_CODES)
            or any(not isinstance(code, str) or code not in _ISSUE_LABELS for code in value)):
        return set()
    return set(value)


def _issue_fingerprint(keys):
    ordered = [key for key in _ISSUE_LABELS if key in keys]
    return hashlib.sha256(json.dumps(ordered, separators=(",", ":")).encode("ascii")).hexdigest()


def _legacy_recovery_verified(fingerprint, conditions):
    """Match an old digest only to independently healthy measured issue kinds.

    The old ledger had no component list. Missing proxy/AI/backup evidence must
    not clear it. The search is bounded by the fixed code catalogue (15 codes),
    not untrusted input; common one-component incidents match immediately.
    """
    healthy = [key for key in FACT_ISSUE_CODES if conditions[key] is False]
    for count in range(1, len(healthy) + 1):
        for group in itertools.combinations(healthy, count):
            if _issue_fingerprint(group) == fingerprint:
                return True
    return False


def _incident_state(value):
    """Strict bounded ledger; never preserve caller text, measurements or keys."""
    if isinstance(value, str):
        if len(value) > 4096:
            return None
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return None
    if (not isinstance(value, dict) or set(value) != {"schema", "open"}
            or type(value.get("schema")) is not int or value["schema"] != 1):
        return None
    opened = value.get("open")
    if (not isinstance(opened, list) or len(opened) > len(_ISSUE_LABELS)
            or any(not isinstance(key, str) or key not in _ISSUE_LABELS for key in opened)
            or len(set(opened)) != len(opened)):
        return None
    return set(opened)


def notification_fingerprint(snapshot):
    """Stable digest of factual failure kinds, unaffected by an AI paraphrase."""
    return _issue_fingerprint({key for key, _ in _fact_issues(snapshot)})


def fact_alert(snapshot, previous_fingerprint="", *, previous_state=None,
               confirmed_issues=None, confirmed_healthy=None):
    """Quiet while healthy/unchanged; announce observed failures or recovery.

    Caller owns bounded cadence and delivery. Pass the last successfully
    delivered state {schema:1, open:[codes]} (dict or JSON), then persist state
    and fingerprint ONLY after successful delivery. Never acknowledge a changed
    unsent candidate during cooldown/failure. A quiet initial healthy baseline
    can be saved, and an unchanged delivered legacy hash can migrate to state.
    state=None means legacy history cannot safely migrate with missing evidence.
    Optional confirmed_issues/confirmed_healthy contain only condition codes
    whose bad/healthy samples the caller has confirmed. Unconfirmed conditions
    become unknown; they cannot create an incident or imply recovery. None
    preserves the backwards-compatible one-sample behavior.
    """
    snapshot = snapshot if isinstance(snapshot, dict) else {}
    conditions, labels = _fact_conditions(snapshot)
    confirmed_bad, confirmed_good = _confirmed_keys(confirmed_issues), _confirmed_keys(confirmed_healthy)
    for key, value in conditions.items():
        if (value is True and confirmed_bad is not None and key not in confirmed_bad
                or value is False and confirmed_good is not None and key not in confirmed_good):
            conditions[key] = None
    issues = [key for key in _ISSUE_LABELS if conditions[key] is True]
    digest = _issue_fingerprint(issues)
    previous = previous_fingerprint if isinstance(previous_fingerprint, str) and re.fullmatch(r"[0-9a-f]{64}", previous_fingerprint) else ""
    # A missing runtime sample must not turn a previously observed failure into
    # a recovery message. Recovery needs complete service/resource evidence.
    server = snapshot.get("server") if isinstance(snapshot.get("server"), dict) else {}
    services = server.get("services") if isinstance(server.get("services"), dict) else {}
    complete = all(_number(server.get(name)) is not None for name in ("cpu_percent", "memory_percent", "disk_percent")) and all(services.get(name) == "active" for name in ("operator", "rospanel", "xray")) and server.get("network_status") == "healthy"
    ai = snapshot.get("ai") if isinstance(snapshot.get("ai"), dict) else {}
    backup = snapshot.get("backup") if isinstance(snapshot.get("backup"), dict) else {}
    complete = complete and type(ai.get("enabled")) is bool and type(backup.get("hourly_enabled")) is bool
    if ai.get("enabled") is True:
        complete = complete and ai.get("last_status") == "готов"
        if ai.get("provider") != "gemini":
            complete = complete and services.get("llama_cpp" if ai.get("engine") == "llama.cpp" else "ollama") == "active"
    if backup.get("hourly_enabled") is True:
        stamp, generated = _integer(backup.get("ts")), _integer(snapshot.get("generated_at"))
        complete = complete and backup.get("exists") is True and backup.get("last_delivery_ok") is True and bool(stamp and generated and 0 <= generated - stamp <= 2 * 3600)
    prior = _incident_state(previous_state)
    resolved, unverified = [], []
    if prior is not None:
        resolved = [key for key in _ISSUE_LABELS if key in prior and conditions[key] is False]
        unverified = [key for key in _ISSUE_LABELS if key in prior and conditions[key] is None]
        opened = set(issues) | set(unverified)
        new = [key for key in issues if key not in prior]
        digest = _issue_fingerprint(opened)
        recovery = bool(prior) and not opened and bool(resolved)
        should_notify = bool(new or resolved)
        state = {"schema": 1, "open": [key for key in _ISSUE_LABELS if key in opened]}
    else:
        recovery = (not issues and bool(previous) and previous != _issue_fingerprint(())
                    and complete and _legacy_recovery_verified(previous, conditions))
        should_notify = digest != previous and (bool(issues) or recovery)
        new = issues if should_notify and not recovery else []
        # An opaque old hash cannot identify components. Keep it until a fully
        # verified recovery or identical factual issue set makes migration safe.
        migratable = not previous or previous == _issue_fingerprint(()) or previous == digest or recovery
        state = {"schema": 1, "open": list(issues)} if migratable else None
        if not issues and previous and not recovery and previous != _issue_fingerprint(()):
            digest = previous
    transition = "recovery" if recovery else "update" if resolved else "incident" if new else "quiet"
    title = ("✅ Quantum Control · проверки восстановились" if recovery else
             "🟡 Quantum Control · частичное восстановление" if resolved else
             "🚨 Quantum Control · требуется внимание")
    lines = [title, f"Срез: {_stamp(snapshot.get('generated_at'))}"]
    if resolved:
        lines.extend(["", "✅ Подтверждённое восстановление"])
        for key in resolved:
            detail = ("успешная доставка подтверждена" if key == "backup_delivery_failed" else
                      "есть свежий архив" if key == "backup_stale" else
                      "успешный анализ" if key == "analysis_error" else
                      "свежий nonce Telegram подтверждён" if key.startswith("proxy_") else
                      "повторные проверки в норме" if key == "network_degraded" else
                      "служба active" if key.startswith("service_") else "замер ниже порога")
            lines.append("• " + _ISSUE_LABELS[key] + ": " + detail)
    elif recovery:
        lines.append("• Серверные службы, ресурсы и сетевые проверки снова в норме.")
    for title, group, action in _GROUPS:
        observed = [key for key in group if key in issues]
        if observed:
            lines.extend(["", title])
            lines.extend("• " + labels[key] for key in observed)
            lines.append("Действие: " + action)
    if unverified and should_notify:
        lines.extend(["", "⏳ Восстановление ещё не подтверждено"])
        lines.append("• Нет нового результата: " + ", ".join(_ISSUE_LABELS[key] for key in unverified))
    if "network_degraded" in issues or "network_degraded" in resolved:
        lines.append("Проверки выполнены с VDS. Причина сбоя пока не установлена. Пинг телефона и скорость VPN не измерялись; ТСПУ не доказана.")
    if "analysis_error" in issues or any(key in issues for key in ("service_ollama", "service_llama_cpp")):
        lines.append("Это ошибка анализа ИИ, не подтверждение сбоя VPN. Монитор нод работает отдельно.")
    if any(key.startswith("proxy_") for key in issues + resolved):
        lines.append("Nonce проверяет ответ протокола, не вход в аккаунт и не путь вашего оператора без VPN.")
        if "proxy_mtproto" in issues and any(conditions[key] is False for key in ("proxy_native_tls", "proxy_web")):
            lines.append("Резерв прошёл серверный тест: откройте «Сеть → Telegram → FakeTLS/WEB» и проверьте подключение с телефона.")
    if should_notify:
        lines.extend(["", "/status — полный отчёт; /backups — состояние копий.",
                      "Инциденты сгруппированы; одинаковые факты повторно не отправляются."])
    return {"fingerprint": digest, "state": state, "should_notify": should_notify,
            "recovery": recovery, "issues": issues, "new_issues": new,
            "resolved_issues": resolved, "unverified_issues": unverified,
            "transition": transition, "message": "\n".join(lines)[:MAX_ALERT_CHARS] if should_notify else ""}


def authorized_command(message, allowed_chat_id, allowed_user_ids=None, bot_username=None):
    """Accept allowlisted read-only commands only from the configured private chat.

    Never authorize group chats, channel posts, forwards, bots or sender_chat.
    An optional explicit sender allowlist cannot broaden the private-chat scope.
    The outer poller owns age/rate/offset checks; this function has no side effects.
    """
    if not isinstance(message, dict) or any(key in message for key in ("forward_origin", "forward_from", "forward_from_chat", "forward_date", "sender_chat")):
        return None
    chat, sender = message.get("chat"), message.get("from")
    if not isinstance(chat, dict) or not isinstance(sender, dict) or chat.get("type") != "private" or sender.get("is_bot") is not False:
        return None
    chat_id = _integer(chat.get("id"), minimum=1)
    configured_id = _integer(allowed_chat_id, minimum=1)
    sender_id = _integer(sender.get("id"), minimum=1)
    if configured_id is None or chat_id != configured_id or sender_id != chat_id:
        return None
    if allowed_user_ids is not None:
        if not isinstance(allowed_user_ids, (list, tuple, set, frozenset)):
            return None
        if sender_id not in {_integer(item, minimum=1) for item in allowed_user_ids}:
            return None
    text = message.get("text")
    if not isinstance(text, str) or not 1 <= len(text) <= 128:
        return None
    match = re.fullmatch(r"(/[a-z_]{1,30})(?:@([A-Za-z0-9_]{5,32}))?", text.strip())
    if not match or match[1] not in COMMANDS:
        return None
    if match[2] and (not isinstance(bot_username, str) or match[2].casefold() != bot_username.casefold()):
        return None
    return match[1]
