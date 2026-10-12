# QuantumVPN speed evidence

Extract `QuantumVPN-speed-evidence-collector.zip` beside `adb.exe`, connect one
Android phone with USB debugging authorized and run
`collect-vpn-speed-evidence-windows.cmd`.

The collector compares the same video and quality with VPN off and VPN on,
records continuous unfiltered system logcat, interface counters, CPU, memory,
connectivity, available netd/thermal state, Android/API/ABI and APK version.
It never installs, clears, restarts the app or changes VPN/network/DNS settings.
Start/stop the VPN yourself when prompted. Each phase lasts 30 seconds.

After the failing VPN phase, export the app diagnostic from Settings ->
Diagnostics without restarting the app. For a release APK, save the Sharesheet
JSON to this computer and enter its full path. For a debug APK, launch the script
with `-Package com.quantumvpn.debug`; it can read the explicit export with `run-as`.

The ZIP on the desktop is private device evidence. Do not publish it as a release
asset. Only the collector program belongs in the test prerelease. A missing JSON
is explicitly marked incomplete; a VPS speed test or emulator capture does not
prove the throughput of the phone-to-VPN route.

The in-app speed probe now measures HTTP body transfer separately from DNS/TLS
setup and rejects empty/rejected responses. It is a bounded single-connection
probe, with at most 32 MB for the primary download, 10 MB for fallback and 4 MiB
upload. Its result is not a multi-connection speedtest capacity benchmark.
