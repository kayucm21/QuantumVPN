package com.quantumvpn.vpn

import android.content.pm.PackageManager
import android.net.VpnService

fun interface PackageAvailability {
    fun isInstalledAndEnabled(packageName: String): Boolean
}

fun interface AllowedApplicationSink {
    fun addAllowedApplication(packageName: String)
}

fun interface DisallowedApplicationSink {
    fun addDisallowedApplication(packageName: String)
}

sealed interface VpnAppScopeResult {
    data class Ready(
        val mode: AppScopeMode,
        val effectivePackages: List<String>,
        val skippedPackages: List<String> = emptyList(),
    ) : VpnAppScopeResult {
        constructor(effectivePackages: List<String>) : this(AppScopeMode.Include, effectivePackages)
    }
    data object EmptyAllowlist : VpnAppScopeResult
    data class MissingApplications(val packageNames: List<String>) : VpnAppScopeResult
    data class BuilderFailure(
        val packageName: String,
        val reason: String,
    ) : VpnAppScopeResult
}

class VpnAppScopePreflight(
    private val ownPackageName: String,
    private val packageAvailability: PackageAvailability,
) {
    fun apply(
        userAllowlist: Set<String>,
        builder: VpnService.Builder,
    ): VpnAppScopeResult = apply(
        selectedPackages = userAllowlist,
        mode = AppScopeMode.Include,
        allowedSink = AllowedApplicationSink(builder::addAllowedApplication),
        disallowedSink = DisallowedApplicationSink(builder::addDisallowedApplication),
    )

    fun apply(
        userAllowlist: Set<String>,
        sink: AllowedApplicationSink,
    ): VpnAppScopeResult = apply(
        selectedPackages = userAllowlist,
        mode = AppScopeMode.Include,
        allowedSink = sink,
        disallowedSink = DisallowedApplicationSink { },
    )

    fun apply(
        selectedPackages: Set<String>,
        mode: AppScopeMode,
        builder: VpnService.Builder,
    ): VpnAppScopeResult = apply(
        selectedPackages,
        mode,
        AllowedApplicationSink(builder::addAllowedApplication),
        DisallowedApplicationSink(builder::addDisallowedApplication),
    )

    fun apply(
        selectedPackages: Set<String>,
        mode: AppScopeMode,
        allowedSink: AllowedApplicationSink,
        disallowedSink: DisallowedApplicationSink,
    ): VpnAppScopeResult {
        if (mode == AppScopeMode.All) {
            // Без addAllowed/addDisallowed Android пропускает в TUN весь трафик устройства.
            return VpnAppScopeResult.Ready(AppScopeMode.All, emptyList())
        }

        val userPackages = normalizePackageNames(selectedPackages, ownPackageName).toList()
        if (userPackages.isEmpty()) return VpnAppScopeResult.EmptyAllowlist

        val missing = userPackages.filterNot(packageAvailability::isInstalledAndEnabled)
        val availableUserPackages = userPackages - missing.toSet()
        if (availableUserPackages.isEmpty()) {
            return VpnAppScopeResult.MissingApplications(missing)
        }
        val effectivePackages = if (mode == AppScopeMode.Include || mode == AppScopeMode.Block) {
            availableUserPackages + ownPackageName
        } else {
            availableUserPackages
        }

        effectivePackages.forEach { packageName ->
            try {
                if (mode == AppScopeMode.Include || mode == AppScopeMode.Block) {
                    allowedSink.addAllowedApplication(packageName)
                } else {
                    disallowedSink.addDisallowedApplication(packageName)
                }
            } catch (failure: Exception) {
                return VpnAppScopeResult.BuilderFailure(
                    packageName = packageName,
                    reason = failure.message?.take(240)
                        ?: failure::class.java.simpleName,
                )
            }
        }
        return VpnAppScopeResult.Ready(mode, effectivePackages, missing)
    }
}

class AndroidPackageAvailability(
    private val packageManager: PackageManager,
) : PackageAvailability {
    override fun isInstalledAndEnabled(packageName: String): Boolean =
        try {
            @Suppress("DEPRECATION")
            packageManager.getApplicationInfo(packageName, 0).enabled
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
}
