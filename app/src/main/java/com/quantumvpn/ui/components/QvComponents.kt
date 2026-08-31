package com.quantumvpn.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.quantumvpn.ui.CosmicTokens

@Composable
fun QvScreen(
    contentPadding: PaddingValues,
    scrollable: Boolean = true,
    content: @Composable ColumnScope.() -> Unit,
) {
    val scroll = rememberScrollState()
    val columnModifier = Modifier
        .fillMaxSize()
        .padding(contentPadding)
        .padding(horizontal = CosmicTokens.Space.lg)
        .then(if (scrollable) Modifier.verticalScroll(scroll) else Modifier)
    Column(
        modifier = columnModifier.padding(bottom = CosmicTokens.Space.xl),
        verticalArrangement = Arrangement.spacedBy(CosmicTokens.Space.md),
        content = content,
    )
}

@Composable
fun QvSection(
    title: String,
    subtitle: String? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(CosmicTokens.Space.sm)) {
        Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        if (!subtitle.isNullOrBlank()) {
            Text(
                subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        QvCard(content = content)
    }
}

@Composable
fun QvCard(
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.92f),
                shape = RoundedCornerShape(CosmicTokens.Radius.md),
            )
            .padding(CosmicTokens.Space.lg),
        verticalArrangement = Arrangement.spacedBy(CosmicTokens.Space.md),
        content = content,
    )
}

@Composable
fun QvToggleRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    testTag: String,
    enabled: Boolean = true,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            .testTag(testTag),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f).padding(end = CosmicTokens.Space.md)) {
            Text(title, fontWeight = FontWeight.Medium)
            Text(
                subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            enabled = enabled,
            modifier = Modifier.semantics { contentDescription = title },
        )
    }
}

@Composable
fun QvNavRow(
    title: String,
    subtitle: String,
    onClick: () -> Unit,
    trailing: String = "›",
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            .clickable(onClick = onClick)
            .padding(vertical = CosmicTokens.Space.sm),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, fontWeight = FontWeight.SemiBold)
            Text(
                subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Text(
            trailing,
            style = MaterialTheme.typography.titleLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
fun QvEmpty(
    title: String,
    body: String,
    action: (@Composable () -> Unit)? = null,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = CosmicTokens.Space.xxl),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(CosmicTokens.Space.sm),
    ) {
        Text(title, style = MaterialTheme.typography.headlineSmall)
        Text(
            body,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        action?.invoke()
    }
}

data class QvTabItem(
    val id: String,
    val title: String,
    val icon: ImageVector,
)

@Composable
fun QvBottomBar(
    tabs: List<QvTabItem>,
    selectedId: String,
    onSelect: (String) -> Unit,
) {
    NavigationBar(
        containerColor = CosmicTokens.Deep,
        contentColor = CosmicTokens.OnVoid,
    ) {
        tabs.forEach { tab ->
            NavigationBarItem(
                selected = tab.id == selectedId,
                onClick = { onSelect(tab.id) },
                icon = { Icon(tab.icon, contentDescription = tab.title) },
                label = { Text(tab.title, maxLines = 1) },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = CosmicTokens.Orbit,
                    selectedTextColor = CosmicTokens.Orbit,
                    indicatorColor = CosmicTokens.Panel,
                    unselectedIconColor = CosmicTokens.OnVoidMuted,
                    unselectedTextColor = CosmicTokens.OnVoidMuted,
                ),
            )
        }
    }
}

@Composable
fun QvHubHeader(title: String, subtitle: String) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                brush = Brush.verticalGradient(
                    listOf(CosmicTokens.Deep, CosmicTokens.Void.copy(alpha = 0.2f)),
                ),
                shape = RoundedCornerShape(CosmicTokens.Radius.lg),
            )
            .padding(CosmicTokens.Space.xl),
        verticalArrangement = Arrangement.spacedBy(CosmicTokens.Space.xs),
    ) {
        Text(title, style = MaterialTheme.typography.headlineSmall, color = CosmicTokens.OnVoid)
        Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = CosmicTokens.OnVoidMuted)
    }
}

@Composable
fun ConnectPulse(enabled: Boolean, reduceMotion: Boolean, content: @Composable () -> Unit) {
    val transition = rememberInfiniteTransition(label = "connect-pulse")
    val animated by transition.animateFloat(
        initialValue = 1f,
        targetValue = 1.04f,
        animationSpec = infiniteRepeatable(
            animation = tween(CosmicTokens.Motion.ConnectPulseMs, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "connect-pulse-scale",
    )
    val pulse = if (enabled && !reduceMotion) animated else 1f
    Box(modifier = Modifier.scale(pulse), content = { content() })
}

@Composable
fun QvDivider() {
    HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f))
}

@Composable
fun RowScope.QvMetricChip(label: String, value: String) {
    Column(
        modifier = Modifier
            .weight(1f)
            .background(
                CosmicTokens.Panel.copy(alpha = 0.65f),
                RoundedCornerShape(CosmicTokens.Radius.sm),
            )
            .padding(CosmicTokens.Space.md),
    ) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = CosmicTokens.OnVoidMuted)
        Text(value, style = MaterialTheme.typography.titleMedium, color = CosmicTokens.OnVoid)
    }
}
