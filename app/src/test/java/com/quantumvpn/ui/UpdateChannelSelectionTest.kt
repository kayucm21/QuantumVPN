package com.quantumvpn.ui

import com.quantumvpn.updates.UpdateChannel
import org.junit.Assert.assertEquals
import org.junit.Test

class UpdateChannelSelectionTest {
    @Test
    fun `stable build defaults to stable when no choice exists for this build`() {
        assertEquals(
            UpdateChannel.Stable,
            resolveUpdateChannel(
                storedChannel = UpdateChannel.Beta.name,
                selectedForBuildId = "previous",
                currentBuildId = "current",
                buildDefault = UpdateChannel.Stable,
            ),
        )
    }

    @Test
    fun `beta build defaults to beta when no choice exists for this build`() {
        assertEquals(
            UpdateChannel.Beta,
            resolveUpdateChannel(
                storedChannel = UpdateChannel.Stable.name,
                selectedForBuildId = "previous",
                currentBuildId = "current",
                buildDefault = UpdateChannel.Beta,
            ),
        )
    }

    @Test
    fun `manual choice is preserved within the current build`() {
        assertEquals(
            UpdateChannel.Beta,
            resolveUpdateChannel(
                storedChannel = UpdateChannel.Beta.name,
                selectedForBuildId = "current",
                currentBuildId = "current",
                buildDefault = UpdateChannel.Stable,
            ),
        )
    }

    @Test
    fun `invalid saved choice falls back to current build channel`() {
        assertEquals(
            UpdateChannel.Beta,
            resolveUpdateChannel(
                storedChannel = "Unknown",
                selectedForBuildId = "current",
                currentBuildId = "current",
                buildDefault = UpdateChannel.Beta,
            ),
        )
    }
}
