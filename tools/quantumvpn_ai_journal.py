"""Deterministic, bounded explanations of measured automatic decisions.

Only registered-node aliases and typed measurements enter this journal. Model
prose, targets, logs, credentials and arbitrary setting values are excluded.
This module neither probes a network nor changes settings.
"""
import hashlib
import json
import math
import re
from itertools import islice

MAX_ENTRY_BYTES = 24576
MAX_NODES = 24
_NODE_ID = re.compile(r"node_[a-f0-9]{16}\Z")
REASONS = {
    "insufficient_data": "Недостаточно свежих последовательных замеров.",
    "operator_disabled": "Оператор остановил автоматические изменения.",
    "no_registered_nodes": "Нет зарегистрированных нод для управления.",
    "stale_report": "Отчёт устарел; нужен свежий замер.",
    "manual_override": "Ручное изменение отменило ожидающий автоматический откат.",
    "reserve_regressed": "Резерв ухудшился, а прежняя нода снова подтверждена исправной.",
    "post_change_checks_passed": "Последовательные проверки после изменения пройдены.",
    "waiting_post_change_checks": "Продолжаются проверки после изменения рекомендации.",
    "monitor_interval": "Следующая проверка будет после заданного интервала наблюдения.",
    "cooldown": "Выдерживается пауза между автоматическими изменениями.",
    "current_node_healthy": "Текущая нода исправна; небольшая разница RTT не меняет рекомендацию.",
    "no_proven_healthy_reserve": "Нет резерва с подтверждённой исправностью.",
    "no_proven_regression": "У текущей ноды ещё нет подтверждённой серии ухудшений.",
    "measured_registered_node_control": "Действие разрешено свежими последовательными замерами.",
}
ACTIONS = {
    "select_reserve": "изменить рекомендацию на резерв",
    "quarantine_node": "временно исключить ноду из рекомендаций",
    "recover_node": "снять собственное автоматическое исключение",
    "rollback": "вернуть предыдущую рекомендацию",
    "verified": "подтвердить изменение контрольными проверками",
    "manual_override": "учесть ручное изменение",
}


def _integer(value, maximum=2**40):
    return value if type(value) is int and 0 <= value <= maximum else None


def _alias(target):
    return "node_" + hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]


def _mapping(value):
    if isinstance(value, str) and len(value) <= MAX_ENTRY_BYTES:
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return {}
    return value if isinstance(value, dict) else {}


def _snapshot(values, aliases):
    """Describe only action keys; never copy arbitrary persisted strings."""
    result = {}
    if "nodes_recommended" in values:
        raw = values["nodes_recommended"]
        result["recommendations"] = [_alias(part.strip()) for part in raw.split(",")[:MAX_NODES]
                                     if part.strip() in aliases] if isinstance(raw, str) else []
    if "load_balancer_last_target" in values:
        target = values["load_balancer_last_target"]
        result["selected_node"] = _alias(target) if isinstance(target, str) and target in aliases else None
    if "node_quarantine" in values:
        quarantine = _mapping(values["node_quarantine"])
        result["quarantined_nodes"] = [_alias(target) for target in sorted(aliases) if target in quarantine]
    if "load_balancer_last_decision" in values:
        raw = values["load_balancer_last_decision"]
        result["decision_at"] = int(raw) if isinstance(raw, str) and re.fullmatch(r"[0-9]{1,12}", raw) else _integer(raw)
    return result


def _clean_snapshot(value):
    value = value if isinstance(value, dict) else {}
    result = {}
    for name in ("recommendations", "quarantined_nodes"):
        if name in value:
            rows = value[name] if isinstance(value[name], list) else []
            result[name] = [item for item in rows[:MAX_NODES] if isinstance(item, str) and _NODE_ID.fullmatch(item)]
    if "selected_node" in value:
        node = value["selected_node"]
        result["selected_node"] = node if isinstance(node, str) and _NODE_ID.fullmatch(node) else None
    if "decision_at" in value:
        result["decision_at"] = _integer(value["decision_at"])
    return result


def sanitize_entry(value):
    """Rebuild persisted entries from enums/numbers, never trust journal prose."""
    value = value if isinstance(value, dict) else {}
    reason = value.get("reason") if isinstance(value.get("reason"), str) and value.get("reason") in REASONS else "insufficient_data"
    status = value.get("status") if value.get("status") in ("disabled", "observing", "stable", "applied", "verifying", "verified") else "observing"
    phase = value.get("phase") if value.get("phase") in ("planned", "applied", "observed") else "observed"
    actions = []
    for raw in islice(value.get("actions", []) if isinstance(value.get("actions"), list) else [], 4):
        if not isinstance(raw, dict):
            continue
        node = raw.get("node_id")
        if isinstance(raw.get("kind"), str) and raw.get("kind") in ACTIONS and isinstance(node, str) and _NODE_ID.fullmatch(node):
            actions.append({"kind": raw["kind"], "node_id": node})
    evidence = []
    for raw in islice(value.get("evidence", []) if isinstance(value.get("evidence"), list) else [], MAX_NODES * 3):
        if not isinstance(raw, dict):
            continue
        node = raw.get("node_id")
        if (not isinstance(node, str) or not _NODE_ID.fullmatch(node)
                or raw.get("stage") not in ("dns", "tcp", "tls")
                or raw.get("status") not in ("healthy", "degraded", "unknown")):
            continue
        row = {"node_id": node, "stage": raw["stage"], "status": raw["status"],
               "checked_at": _integer(raw.get("checked_at")),
               "consecutive_checks": _integer(raw.get("consecutive_checks"), 1000)}
        delay = raw.get("latency_ms")
        row["latency_ms"] = round(delay, 1) if type(delay) in (int, float) and 0 <= delay <= 600000 and math.isfinite(delay) else None
        evidence.append(row)
    result = {"schema": 1, "at": _integer(value.get("at")), "phase": phase,
              "status": status, "reason": reason, "why": REASONS[reason],
              "actions": actions, "evidence": evidence,
              "before": _clean_snapshot(value.get("before")), "after": _clean_snapshot(value.get("after")),
              "rollback_available": value.get("rollback_available") is True,
              "scope": "recommendations_only"}
    policy = value.get("policy") if isinstance(value.get("policy"), dict) else {}
    result["policy"] = {}
    for name, default, minimum, maximum in (("monitor_interval_seconds", 60, 60, 3600),
                                             ("action_cooldown_seconds", 900, 300, 86400),
                                             ("required_checks", 3, 3, 10)):
        number = _integer(policy.get(name), maximum)
        result["policy"][name] = number if number is not None and number >= minimum else default
    result["action"] = "; ".join(ACTIONS[row["kind"]] + ": " + row["node_id"] for row in actions) or "Продолжать наблюдение без изменения настроек."
    return result


def build_entry(plan, report, registered, settings, *, phase="planned"):
    """Create an explanatory record using the same report as the planner."""
    registered = set(islice(registered, MAX_NODES))
    now = _integer(plan.get("generated_at")) or 0
    evidence, latest = [], {}
    stages = report.get("stages") if isinstance(report, dict) and isinstance(report.get("stages"), list) else []
    for raw in islice(stages, MAX_NODES * 3):
        if not isinstance(raw, dict) or not isinstance(raw.get("target"), str) or raw.get("target") not in registered:
            continue
        stamp = _integer(raw.get("checked_at"))
        if not stamp or stamp > now or now - stamp > 300 or raw.get("stage") not in ("dns", "tcp", "tls"):
            continue
        key = (raw["target"], raw["stage"])
        if key not in latest or stamp > latest[key]["checked_at"]:
            latest[key] = raw
    for raw in latest.values():
        checks = raw.get("recovery_checks") if raw.get("status") == "healthy" else max(
            _integer(raw.get("failure_checks")) or 0, _integer(raw.get("regression_checks")) or 0)
        evidence.append({"node_id": _alias(raw["target"]), "stage": raw.get("stage"), "status": raw.get("status"),
                         "checked_at": raw["checked_at"], "consecutive_checks": checks, "latency_ms": raw.get("latency_ms")})
    changes = plan.get("changes") if isinstance(plan.get("changes"), dict) else {}
    before = {key: settings.get(key, "") for key in changes}
    return sanitize_entry({"schema": 1, "at": now, "phase": phase, "status": plan.get("status"), "reason": plan.get("reason"),
                           "actions": [{"kind": row.get("kind"), "node_id": _alias(row["target"])}
                                       for row in plan.get("actions", []) if isinstance(row, dict) and isinstance(row.get("target"), str) and row.get("target") in registered],
                           "evidence": evidence, "before": _snapshot(before, registered), "after": _snapshot(changes, registered),
                           "rollback_available": bool(plan.get("state", {}).get("pending")), "policy": plan.get("policy")})


def _describe_snapshot(snapshot):
    labels = {"recommendations": "рекомендация", "selected_node": "выбранная нода",
              "quarantined_nodes": "временные исключения", "decision_at": "время решения"}
    parts = []
    for name, value in snapshot.items():
        if isinstance(value, list):
            shown = ", ".join(value) or "нет"
        else:
            shown = str(value) if value is not None else "не задано"
        parts.append(labels[name] + " — " + shown)
    return "; ".join(parts) or "Настройки не изменены."


def render_entry(entry):
    """Readable Russian journal; all text is generated from a typed entry."""
    entry = sanitize_entry(entry)
    phases = {"planned": "План проверен", "applied": "Изменение применено", "observed": "Наблюдение"}
    lines = [phases[entry["phase"]] + ". " + entry["why"], "Действие: " + entry["action"]]
    policy = entry["policy"]
    lines.append("Политика: интервал наблюдения " + str(policy["monitor_interval_seconds"]) + " с; пауза между изменениями "
                 + str(policy["action_cooldown_seconds"]) + " с; последовательных проверок требуется " + str(policy["required_checks"]) + ".")
    facts = []
    statuses = {"healthy": "исправно", "degraded": "ухудшение", "unknown": "нет данных"}
    for row in entry["evidence"]:
        text = row["node_id"] + " / " + row["stage"].upper() + ": " + statuses[row["status"]]
        if row["consecutive_checks"] is not None:
            text += ", последовательных проверок " + str(row["consecutive_checks"])
        if row["latency_ms"] is not None:
            text += ", RTT " + str(row["latency_ms"]) + " мс"
        facts.append(text)
    lines.append("Доказательства: " + ("; ".join(facts) or "Свежих проверок нет."))
    lines.extend(["До: " + _describe_snapshot(entry["before"]), "После: " + _describe_snapshot(entry["after"]),
                  "Откат: " + ("доступен, если настройки остаются автоматическими и прежняя нода подтверждена исправной." if entry["rollback_available"] else "ожидающего отката нет."),
                  "Область действия: рекомендации панели; активные VPN-сеансы не переключаются."])
    return "\n".join(lines)


def read_entries(db, limit=20):
    limit = limit if type(limit) is int else 20
    limit = max(1, min(100, limit))
    rows = db.execute("select detail from events where kind='ai_autopilot_decision' order by ts desc,rowid desc limit ?", (limit,)).fetchall()
    result = []
    for row in rows:
        raw = row[0]
        if not isinstance(raw, str) or len(raw) > MAX_ENTRY_BYTES:
            continue
        try:
            entry = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if isinstance(entry, dict) and entry.get("schema") == 1:
            result.append(sanitize_entry(entry))
    return result
