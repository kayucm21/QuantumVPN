"""Pure confirmation gates for factual bot alerts; no model, network or shell."""
from __future__ import annotations

SAMPLES = 3
MIN_SAMPLE_SECONDS = 30
MAX_SAMPLE_GAP = 180
DELIVERY_INTERVAL_SECONDS = 60


def confirmed_conditions(observation, previous=None, *, now, open_issues=()):
    """Require spaced consecutive observations; missing data never heals a fault.

    Delivered open faults remain admitted while bad. Both a new fault and a
    recovery require three fresh samples. This state is disposable; the separate
    delivered incident ledger must survive process restart.
    """
    if type(now) is not int or now < 0:
        raise ValueError("invalid_clock")
    raw = observation.get("conditions", {}) if isinstance(observation, dict) else {}
    if not isinstance(raw, dict) or len(raw) > 64:
        raw = {}
    old = previous if isinstance(previous, dict) else {}
    timestamps = observation.get("sample_timestamps", {}) if isinstance(observation, dict) else {}
    timestamps = timestamps if isinstance(timestamps, dict) else {}
    state, bad, healthy = {}, [], []
    for code, condition in raw.items():
        if not isinstance(code, str) or len(code) > 64 or not isinstance(condition, str) or condition not in {"bad", "healthy", "unknown"}:
            continue
        item = old.get(code)
        item = item if isinstance(item, dict) else {}
        stamp, count = item.get("ts"), item.get("count")
        measured = timestamps.get(code) if code in timestamps else None
        has_measurement = code in timestamps
        if has_measurement and (type(measured) is not int or not 0 <= now - measured <= 900):
            condition = "unknown"
        valid = (type(stamp) is int and type(count) is int and 0 <= count <= SAMPLES
                 and 0 <= now - stamp <= (900 if has_measurement else MAX_SAMPLE_GAP)
                 and item.get("condition") == condition)
        if condition == "unknown":
            count, stamp = 0, now
        elif valid and (now - stamp < MIN_SAMPLE_SECONDS or has_measurement and item.get("measurement_ts") == measured):
            pass
        else:
            count, stamp = min(SAMPLES, count + 1) if valid else 1, now
        state[code] = {"condition": condition, "count": count, "ts": stamp}
        if has_measurement:
            state[code]["measurement_ts"] = measured
        if condition == "bad" and (count >= SAMPLES or code in open_issues):
            bad.append(code)
        if condition == "healthy" and count >= SAMPLES:
            healthy.append(code)
    return {"state": state, "bad": bad, "healthy": healthy}


def delivery_due(factual, *, now, last_attempt=0, last_sent=0):
    """Changed unsent candidates remain retryable, with bounded Telegram traffic."""
    if not isinstance(factual, dict) or factual.get("should_notify") is not True:
        return False
    if type(now) is not int or now < 0:
        return False
    for stamp in (last_attempt, last_sent):
        if type(stamp) is not int or stamp < 0:
            return False
        if stamp and now - stamp < DELIVERY_INTERVAL_SECONDS:
            return False
    return True


def backup_test_summary(result):
    """Allowlisted test facts only; never pass archive members/exception text."""
    result = result if isinstance(result, dict) else {}
    checked = result.get("checked_at")
    databases, missing = result.get("databases"), result.get("missing")
    ok = result.get("ok") if type(result.get("ok")) is bool else None
    count = len(set(databases) & {"operator.db", "rospanel.db"}) if isinstance(databases, list) and all(isinstance(x, str) for x in databases) else None
    absent = len(missing) if isinstance(missing, list) and len(missing) <= 6 else None
    return {"backup_verified": ok,
            "backup_checked_at": checked if type(checked) is int and checked > 0 else None,
            "backup_db_count": count, "backup_missing_count": absent}


def format_backup_tests(result):
    facts = backup_test_summary(result)
    if facts["backup_verified"] is not True:
        return "🧪 Проверка копии: ❌ не пройдена. Архив не отправлен; действующие базы не изменялись."
    absent = facts["backup_missing_count"]
    return ("🧪 Проверка копии: ✅ AES-256-GCM, ZIP и SQLite проверены в изолированном каталоге.\n"
            f"Баз данных: {facts['backup_db_count']}/2 · недостающих компонентов: {absent if absent is not None else 'нет данных'}.\n"
            "Это проверка восстановления баз, не полный запуск VDS. Внешний ключ расшифровки хранится отдельно.")
