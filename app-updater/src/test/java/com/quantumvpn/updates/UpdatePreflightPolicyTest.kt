package com.quantumvpn.updates

import org.junit.Assert.*
import org.junit.Test

class UpdatePreflightPolicyTest {
    @Test fun resumedDownloadOnlyReservesRemainingTransferAndInstallerCopy() {
        assertEquals(200L + UpdateStoragePolicy.HEADROOM_BYTES, UpdateStoragePolicy.requiredDownloadBytes(100L))
        assertEquals(125L + UpdateStoragePolicy.HEADROOM_BYTES, UpdateStoragePolicy.requiredDownloadBytes(100L, 75L))
        assertEquals(100L + UpdateStoragePolicy.HEADROOM_BYTES, UpdateStoragePolicy.requiredDownloadBytes(100L, Long.MAX_VALUE))
        assertEquals(200L + UpdateStoragePolicy.HEADROOM_BYTES, UpdateStoragePolicy.requiredDownloadBytes(100L, -10L))
    }

    @Test fun insufficientSpaceFailsBeforeAnyDownloadOrInstall() {
        assertThrows(UpdateException::class.java) { UpdateStoragePolicy.requireDownloadSpace(100L, 0L) }
        assertThrows(UpdateException::class.java) { UpdateStoragePolicy.requireInstallerSpace(100L, -1L) }
        UpdateStoragePolicy.requireDownloadSpace(100L, 200L + UpdateStoragePolicy.HEADROOM_BYTES)
        UpdateStoragePolicy.requireInstallerSpace(100L, 100L + UpdateStoragePolicy.HEADROOM_BYTES)
    }

    @Test fun untrustedOrOverflowingSizesAreRejected() {
        listOf(0L, -1L, Long.MAX_VALUE).forEach { invalid ->
            assertThrows(IllegalArgumentException::class.java) { UpdateStoragePolicy.requiredDownloadBytes(invalid) }
        }
    }

    @Test fun documentedTargetThresholdsAndSelfUpdateAreRequired() {
        val thresholds = mapOf(31 to 29, 32 to 29, 33 to 30, 34 to 31, 35 to 33, 36 to 34, 37 to 35)
        thresholds.forEach { (device, minimum) ->
            assertTrue(allowed(device, minimum))
            assertFalse(allowed(device, minimum - 1))
        }
        listOf(26, 30, 38, Int.MAX_VALUE).forEach { assertFalse(allowed(it, 100)) }
        assertFalse(SelfUpdateUserActionPolicy.mayRequestWithoutUserAction(36, 37, "app", "other", true, true))
        assertFalse(SelfUpdateUserActionPolicy.mayRequestWithoutUserAction(36, 37, "app", "app", false, true))
        assertFalse(SelfUpdateUserActionPolicy.mayRequestWithoutUserAction(36, 37, "app", "app", true, false))
    }

    private fun allowed(device: Int, target: Int) =
        SelfUpdateUserActionPolicy.mayRequestWithoutUserAction(device, target, "app", "app", true, true)

    @Test fun callbacksRequireActionNonceAndBothSessionIds() {
        assertTrue(UpdateSessionPolicy.acceptsCallback(7, "nonce", 7, 7, "nonce", true))
        assertFalse(UpdateSessionPolicy.acceptsCallback(7, "nonce", 7, 7, "nonce", false))
        assertFalse(UpdateSessionPolicy.acceptsCallback(-1, "nonce", -1, -1, "nonce", true))
        assertFalse(UpdateSessionPolicy.acceptsCallback(7, null, 7, 7, null, true))
        assertFalse(UpdateSessionPolicy.acceptsCallback(7, "", 7, 7, "", true))
        assertFalse(UpdateSessionPolicy.acceptsCallback(7, "nonce", 8, 7, "nonce", true))
        assertFalse(UpdateSessionPolicy.acceptsCallback(7, "nonce", 7, 8, "nonce", true))
        assertFalse(UpdateSessionPolicy.acceptsCallback(7, "nonce", 7, 7, "old nonce", true))
    }

    @Test fun installerSuccessRequiresObservedInstalledVersion() {
        assertFalse(UpdateSessionPolicy.installedVersionProvesSuccess(2, 1))
        assertFalse(UpdateSessionPolicy.installedVersionProvesSuccess(0, 2))
        assertFalse(UpdateSessionPolicy.installedVersionProvesSuccess(2, -1))
        assertTrue(UpdateSessionPolicy.installedVersionProvesSuccess(2, 2))
        assertTrue(UpdateSessionPolicy.installedVersionProvesSuccess(2, 3))
    }

    @Test fun foregroundRecoveryPreservesLiveWorkButAbandonsLostUi() {
        assertTrue(UpdateSessionPolicy.shouldAbandonOnForeground(false, "committed", false, false, false))
        assertTrue(UpdateSessionPolicy.shouldAbandonOnForeground(true, "preparing", false, false, false))
        assertFalse(UpdateSessionPolicy.shouldAbandonOnForeground(true, "preparing", true, false, false))
        assertTrue(UpdateSessionPolicy.shouldAbandonOnForeground(true, "confirmation", false, false, false))
        assertFalse(UpdateSessionPolicy.shouldAbandonOnForeground(true, "confirmation", false, true, false))
        assertTrue(UpdateSessionPolicy.shouldAbandonOnForeground(true, "confirmation_launched", false, false, false))
        assertFalse(UpdateSessionPolicy.shouldAbandonOnForeground(true, "confirmation_launched", false, false, true))
        assertFalse(UpdateSessionPolicy.shouldAbandonOnForeground(true, "committed", false, false, false))
    }
}
