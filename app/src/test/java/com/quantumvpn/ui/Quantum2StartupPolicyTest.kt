package com.quantumvpn.ui

import com.quantumvpn.updates.GitHubAsset
import com.quantumvpn.updates.GitHubRelease
import com.quantumvpn.updates.ReleaseMetadata
import com.quantumvpn.updates.UpdateCandidate
import com.quantumvpn.updates.UpdateOperation
import com.quantumvpn.updates.UpdateState
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class Quantum2StartupPolicyTest {
    @Test fun initializationIsRequiredForEveryUpdaterState() {
        allStates().forEach { state -> assertFalse("Not initialized: $state", startupFinishAllowed(false, state)) }
    }

    @Test fun updateCheckDownloadRetryAndInstallNeverSkipToHome() {
        allStates().filterNot { it is UpdateState.UpToDate || it is UpdateState.Failure || it is UpdateState.Idle ||
            it is UpdateState.Installed || it is UpdateState.InstallCancelled }
            .forEach { state -> assertFalse("Update gate must hold: $state", startupFinishAllowed(true, state)) }
    }

    @Test fun settledChecksAndCompletedHandoffMayEnterInitializedApp() {
        assertTrue(startupFinishAllowed(true, UpdateState.UpToDate("vfixture", "fixture")))
        assertTrue(startupFinishAllowed(true, UpdateState.Failure("Offline fixture")))
        // MainActivity only supplies ready=true for Idle after completed install handoff.
        assertTrue(startupFinishAllowed(true, UpdateState.Idle))
        assertTrue(startupFinishAllowed(true, UpdateState.Installed("fixture", 2L)))
        assertTrue(startupFinishAllowed(true, UpdateState.InstallCancelled(candidate)))
    }

    private fun allStates(): List<UpdateState> = listOf(
        UpdateState.Idle,
        UpdateState.Checking("Stable"),
        UpdateState.RetryingViaVpn(UpdateOperation.Check),
        UpdateState.RetryingViaVpn(UpdateOperation.Download, candidate),
        UpdateState.UpToDate("vfixture", "fixture"),
        UpdateState.Available(candidate),
        UpdateState.Downloading(candidate, 0, 100),
        UpdateState.Downloading(candidate, 100, 100),
        UpdateState.Ready(candidate),
        UpdateState.Installing(candidate),
        UpdateState.Installing(candidate, requiresUserAction = true),
        UpdateState.Installed("fixture", 2L),
        UpdateState.InstallCancelled(candidate),
        UpdateState.Failure("Offline fixture"),
    )

    private val candidate: UpdateCandidate by lazy {
        val apk = GitHubAsset("fixture.apk", "https://example.invalid/fixture.apk", 100, null)
        UpdateCandidate(
            GitHubRelease("vfixture", "Fixture", "", "https://example.invalid/fixture", false, true, listOf(apk)),
            ReleaseMetadata("fixture", 1, "com.quantumvpn", "fixture", "0".repeat(40), listOf("arm64-v8a"), apk.name, "0".repeat(64), 100),
            apk,
            GitHubAsset("fixture.apk.sha256", "https://example.invalid/fixture.apk.sha256", 80, null),
        )
    }
}
