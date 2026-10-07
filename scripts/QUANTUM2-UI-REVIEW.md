# QuantumVPN: disposable Windows UI review

This helper is for a developer checkout, not installation on a user's phone.
Extract `quantum2-review-avd.ps1` into the checkout's `scripts` directory.
Use PowerShell 7.2+, Java 17 and the official Android SDK. The default SDK path
can be overridden with `-SdkRoot`. Existing physical devices and other AVDs are
not modified; the script verifies the exact disposable AVD before installation.

Build the x86_64 app and focused instrumentation APK first with the project
Gradle wrapper and `-PzapretAbi=x86_64 -PquantumUiReviewOnly=true`.
The ordinary build and CI continue to include the complete instrumentation suite.

Run the file with `-Mode Prepare`, then `-Mode Boot -HoldProcess` in a separate
terminal. Once Android is ready, run `-Mode RunTests`, `-Mode Capture` and finally
`-Mode Stop`. Use the same `-AndroidApi 26` or `-AndroidApi 35` on every command.
The default is API 35; API 26 uses a separate dedicated AVD and artifact folder.
If ADB does not discover the emulator, its local ADB port is 5583.
The default renderer remains `swiftshader`. For a renderer-specific capture
failure, `-Mode Boot -Gpu swangle` is an explicit diagnostic alternative; it
does not change the app APK or skip behavioral assertions.

The helper installs only already-built `com.quantumvpn.debug` and
`com.quantumvpn.debug.test` APKs on this disposable x86_64 emulator. It does not
clear app data, import a subscription, change DNS or enable VPN. Captured images
are UI fixtures, not proof of real VPN connectivity or physical-device behavior.
Review all diagnostics before sharing them; never publish raw user/device logs.

The release ZIP contains this README and the checked-in review/evidence helpers
only, not APKs, SDK binaries, credentials or diagnostic captures.
