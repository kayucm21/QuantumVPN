# R8 full mode obfuscation for release builds (Play-compatible).
-allowaccessmodification
-repackageclasses ''
-overloadaggressively

# Keep Android / Compose entry points.
-keep class com.quantumvpn.MainActivity { *; }
-keep class com.quantumvpn.QuantumVpnApplication { *; }
-keep class com.quantumvpn.vpn.QuantumVpnService { *; }

# Libbox JNI / AAR surface.
-keep class io.nekohasekai.libbox.** { *; }
-dontwarn io.nekohasekai.libbox.**

# Android Keystore vault
-keepclassmembers class com.quantumvpn.security.SecureVault { *; }
