#!/usr/bin/env python3
"""Bound the reviewed background/runtime owners; additions require explicit review.

This is a source policy check, not proof of physical-device energy/performance.
The extended client deliberately has more background work than the original MVP.
"""

from pathlib import Path
import re
import sys


DELAY_ALLOWLIST = {
    # UI-only feedback, visible measurements, and bounded installer polling.
    "app/src/main/java/com/quantumvpn/MainActivity.kt": 2,
    "app/src/main/java/com/quantumvpn/community/CommunityScreens.kt": 1,
    "app/src/main/java/com/quantumvpn/ui/HomeScreen.kt": 4,
    "app/src/main/java/com/quantumvpn/ui/QuantumVpnApp.kt": 5,
    "app/src/main/java/com/quantumvpn/ui/QuantumVpnAppV2.kt": 11,
    # Explicit extended-product policy/subscription, reconnect and schedules.
    "app/src/main/java/com/quantumvpn/policy/ClientPolicyRepository.kt": 1,
    "app/src/main/java/com/quantumvpn/profiles/ProfilesViewModel.kt": 1,
    "app/src/main/java/com/quantumvpn/vpn/QuantumVpnService.kt": 7,
    "app/src/main/java/com/quantumvpn/vpn/VpnScheduleCoordinator.kt": 1,
    "app/src/main/java/com/quantumvpn/vpn/WifiAutoConnectCoordinator.kt": 2,
    # One updater retry and the underlying-network debounce.
    "app-updater/src/main/java/com/quantumvpn/updates/UpdateController.kt": 1,
    "network-bootstrap/src/main/java/com/quantumvpn/networkbootstrap/UnderlyingNetworkMonitor.kt": 1,
}

VPN_SERVICE = "app/src/main/java/com/quantumvpn/vpn/QuantumVpnService.kt"
POWER_OWNERS = {VPN_SERVICE, "app/src/main/java/com/quantumvpn/vpn/VpnBatteryExemption.kt"}
ALARM_OWNERS = {
    "app/src/main/java/com/quantumvpn/vpn/SubscriptionRefreshAlarms.kt",
    "app/src/main/java/com/quantumvpn/vpn/UpdateCheckAlarms.kt",
    "app/src/main/java/com/quantumvpn/vpn/VpnScheduleAlarms.kt",
}
CLIPBOARD_WRITE_ALLOWLIST = {
    "app/src/main/java/com/quantumvpn/importer/ProfileImporter.kt": 1,
    "app/src/main/java/com/quantumvpn/ui/QuantumVpnApp.kt": 1,
    "app/src/main/java/com/quantumvpn/ui/ServersScreen.kt": 1,
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def production_sources(root: Path) -> dict[str, str]:
    sources = {}
    for module in ("app", "app-updater", "network-bootstrap", "wireguard-import"):
        for path in (root / module / "src/main/java").rglob("*.kt"):
            sources[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8")
    return sources


def verify_source_surfaces(sources: dict[str, str]) -> None:

    # Counting exact approved call sites catches new timers even inside an owner.
    delays = {path: text.count("delay(") for path, text in sources.items() if "delay(" in text}
    require(delays == DELAY_ALLOWLIST, f"Production timer/retry surface changed: {delays!r}")

    copies = {path: text.count("setPrimaryClip(") for path, text in sources.items() if "setPrimaryClip(" in text}
    require(copies == CLIPBOARD_WRITE_ALLOWLIST, f"Unreviewed clipboard write surface: {copies!r}")
    for path, text in sources.items():
        require("addPrimaryClipChangedListener" not in text, f"Clipboard history listener in {path}")
    importer = sources["app/src/main/java/com/quantumvpn/importer/ProfileImporter.kt"]
    require('clipboard.setPrimaryClip(android.content.ClipData.newPlainText("", ""))' in importer,
            "Importer clipboard write must be only the API 26 clearing fallback")
    require("onCopyExitIp = {" in sources["app/src/main/java/com/quantumvpn/ui/QuantumVpnApp.kt"],
            "Exit IP clipboard copy must remain an explicit UI action")
    require('Text("Копировать тег")' in sources["app/src/main/java/com/quantumvpn/ui/ServersScreen.kt"],
            "Server tag clipboard copy must remain an explicit UI action")

    for name, pattern, expected in (
        ("PowerManager", r"(?:import\s+android\.os\.PowerManager\b|android\.os\.PowerManager(?:\.|::))", POWER_OWNERS),
        ("AlarmManager", r"(?:import\s+android\.app\.AlarmManager\b|android\.app\.AlarmManager(?:\.|::))", ALARM_OWNERS),
        ("CommandConnections", r"\bCommandConnections\b", {VPN_SERVICE}),
    ):
        owners = {path for path, text in sources.items() if re.search(pattern, text)}
        require(owners == expected, f"Unreviewed {name} owner set: {sorted(owners)!r}")

    forbidden = re.compile(
        r"android\.app\.job\.JobScheduler|androidx\.work|ScheduledExecutorService|"
        r"scheduleAtFixedRate|scheduleWithFixedDelay|\bsetExact(?:AndAllowWhileIdle)?\s*\(|\bsetAlarmClock\s*\("
    )
    for path, text in sources.items():
        require(not forbidden.search(text), f"Unreviewed job/exact/periodic scheduler in {path}")
        if path != VPN_SERVICE:
            require("newWakeLock(" not in text, f"WakeLock construction outside VPN service: {path}")

    service = sources[VPN_SERVICE]
    require(service.count("newWakeLock(") == 1, "Exactly one VPN session WakeLock owner is allowed")
    for fragment in (
        'PowerManager.PARTIAL_WAKE_LOCK, "QuantumVPN:session"',
        "setReferenceCounted(false)", "acquire(6 * 60 * 60 * 1000L)",
        "wakeLock?.takeIf { it.isHeld }?.release()", "wakeLock = null",
    ):
        require(fragment in service, f"Missing bounded VPN WakeLock policy: {fragment}")
    require(service.count("releaseWakeLock()") >= 6, "VPN stop/error/revoke WakeLock cleanup surface shrank")
    require(not re.search(r"\bacquire\s*\(\s*\)", service), "VPN WakeLock must always have a timeout")

    # The current service deliberately collects block events and notification rates.
    # Keep one session-owned client, a one-second interval and generation cleanup.
    for fragment in (
        "if (closing.get() || statusClient != null) return",
        "addCommand(Libbox.CommandStatus)", "addCommand(Libbox.CommandConnections)",
        "statusInterval = STATUS_INTERVAL_NANOS",
        "private const val STATUS_INTERVAL_NANOS = 1_000_000_000L",
        "if (generation != controller.currentGeneration()) return",
        "session.closeStatusClient(controller)",
        "runCatching { current?.disconnect() }",
    ):
        require(fragment in service, f"Missing bounded status/connection stream policy: {fragment}")
    require(service.count("addCommand(Libbox.CommandConnections)") == 1, "Connection event clients must not multiply")

    for path in ALARM_OWNERS:
        text = sources[path]
        require("PendingIntent.FLAG_IMMUTABLE" in text, f"Mutable alarm PendingIntent in {path}")
        require("am.cancel(pi)" in text, f"Alarm replacement must cancel the prior PendingIntent: {path}")
        require(
            ".setPackage(context.packageName)" in text or "Intent(context, VpnScheduleAlarmReceiver::class.java)" in text,
            f"Alarm broadcast must target this application: {path}",
        )
    subscription = sources["app/src/main/java/com/quantumvpn/vpn/SubscriptionRefreshAlarms.kt"]
    require("setInexactRepeating(" in subscription and "AlarmManager.INTERVAL_HOUR" in subscription,
            "Subscription refresh must use inexact hourly scheduling")
    schedule = sources["app/src/main/java/com/quantumvpn/vpn/VpnScheduleAlarms.kt"]
    require(schedule.count("setInexactRepeating(") == 3 and schedule.count("if (!enabled) return") == 3,
            "Only the three explicitly enabled inexact VPN schedules are approved")
    update = sources["app/src/main/java/com/quantumvpn/vpn/UpdateCheckAlarms.kt"]
    require("const val INTERVAL_MS = 120L * 1000L" in update and "autoDownload = false" in update,
            "Update alarms must retain their interval and require user download action")


def verify_runtime_surfaces(root: Path) -> None:
    verify_source_surfaces(production_sources(root))


if __name__ == "__main__":
    try:
        verify_runtime_surfaces(Path(sys.argv[1]))
    except (ValueError, KeyError) as error:
        raise SystemExit(str(error)) from error
    print("Reviewed clipboard, timer, wake, alarm and session-connection owner surfaces verified.")
