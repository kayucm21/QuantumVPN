package com.quantumvpn.updates

/** Conservative estimates, not an assertion that PackageInstaller will accept the update. */
object UpdateStoragePolicy {
    const val HEADROOM_BYTES = 32L * 1024L * 1024L

    fun requiredDownloadBytes(apkBytes: Long, alreadyDownloadedBytes: Long = 0L): Long {
        require(apkBytes in 1..UpdateJson.MAX_APK_BYTES)
        val remaining = apkBytes - alreadyDownloadedBytes.coerceIn(0L, apkBytes)
        // One downloaded APK and a second copy owned by PackageInstaller may coexist.
        return remaining + apkBytes + HEADROOM_BYTES
    }

    fun requireDownloadSpace(apkBytes: Long, usableBytes: Long, alreadyDownloadedBytes: Long = 0L) {
        val required = requiredDownloadBytes(apkBytes, alreadyDownloadedBytes)
        if (usableBytes < required) throw UpdateException(
            "Недостаточно свободного места для обновления. Нужно ещё не менее ${megabytes(required - usableBytes.coerceAtLeast(0L))} МБ.",
        )
    }

    fun requireInstallerSpace(apkBytes: Long, usableBytes: Long) {
        require(apkBytes in 1..UpdateJson.MAX_APK_BYTES)
        if (usableBytes < apkBytes + HEADROOM_BYTES) throw UpdateException(
            "Недостаточно свободного места для системной установки. Освободите память и повторите обновление.",
        )
    }

    private fun megabytes(bytes: Long): Long = (bytes + 1024L * 1024L - 1L) / (1024L * 1024L)
}

/** Android's documented self-update eligibility. The system still has the final decision. */
object SelfUpdateUserActionPolicy {
    fun mayRequestWithoutUserAction(
        deviceSdk: Int,
        archiveTargetSdk: Int,
        installedPackage: String,
        archivePackage: String,
        canRequestPackageInstalls: Boolean,
        declaresUpdatePermission: Boolean,
    ): Boolean {
        val targetMinimum = when (deviceSdk) {
            31, 32 -> 29
            33 -> 30
            34 -> 31
            35 -> 33
            36 -> 34
            37 -> 35
            // Requirements advance; a future OS must use the confirmation fallback until reviewed.
            else -> return false
        }
        return installedPackage.isNotBlank() && installedPackage == archivePackage &&
            archiveTargetSdk >= targetMinimum && canRequestPackageInstalls && declaresUpdatePermission
    }
}

/** Authentication and recovery decisions are pure so edge cases can be tested without a device. */
object UpdateSessionPolicy {
    fun acceptsCallback(
        expectedSession: Int, expectedToken: String?, receivedSession: Int,
        installerSession: Int, receivedToken: String?, correctAction: Boolean,
    ): Boolean = correctAction && expectedSession >= 0 && !expectedToken.isNullOrBlank() &&
        expectedSession == receivedSession && expectedSession == installerSession && expectedToken == receivedToken

    fun installedVersionProvesSuccess(expectedVersion: Long, installedVersion: Long): Boolean =
        expectedVersion > 0 && installedVersion >= expectedVersion

    fun shouldAbandonOnForeground(
        sessionExists: Boolean, phase: String, preparingInThisProcess: Boolean,
        hasConfirmationIntent: Boolean, confirmationUiInThisProcess: Boolean,
    ): Boolean = !sessionExists ||
        (phase == "preparing" && !preparingInThisProcess) ||
        (phase == "confirmation" && !hasConfirmationIntent) ||
        (phase == "confirmation_launched" && !confirmationUiInThisProcess)
}
