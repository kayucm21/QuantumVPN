package com.quantumvpn.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

internal fun auroraHomeGreeting(displayName: String): String =
    displayName.trim().takeIf(String::isNotBlank)?.let { "Привет, $it" } ?: "Добро пожаловать"

internal fun auroraHomeInitial(displayName: String): String {
    val name = displayName.trim()
    return if (name.isBlank()) "" else String(Character.toChars(name.codePointAt(0))).uppercase()
}

@Composable
internal fun AuroraHomeWordmark2026(name: String, textColor: Color, accent: Color, modifier: Modifier = Modifier) {
    val wordmark = buildAnnotatedString {
        if (name == "QuantumVPN") {
            append("Quantum")
            withStyle(SpanStyle(color = accent)) { append("VPN") }
        } else append(name)
    }
    Text(wordmark, color = textColor, fontSize = 20.sp, fontWeight = FontWeight.Bold,
        maxLines = 1, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis, modifier = modifier)
}

/** The mockup's Q mark stays crisp at every text/display size. */
@Composable
internal fun AuroraQMark2026(
    modifier: Modifier = Modifier,
    accent: Color = Color(0xFF21E9EE),
) {
    val customLogo = LocalResourceLogo.current
    if (customLogo != null) {
        Image(customLogo.asImageBitmap(), null, modifier, contentScale = ContentScale.Fit)
        return
    }
    Canvas(modifier) {
        val span = size.minDimension
        val center = Offset(size.width * .48f, size.height * .43f)
        drawCircle(
            brush = Brush.linearGradient(listOf(Color(0xFF19B8F2), accent)),
            radius = span * .34f,
            center = center,
            style = Stroke(span * .17f),
        )
        val tail = Path().apply {
            moveTo(center.x - span * .015f, center.y + span * .12f)
            cubicTo(center.x + span * .22f, center.y + span * .12f,
                center.x + span * .23f, center.y + span * .34f,
                center.x + span * .44f, center.y + span * .43f)
            cubicTo(center.x + span * .10f, center.y + span * .53f,
                center.x + span * .04f, center.y + span * .33f,
                center.x - span * .015f, center.y + span * .12f)
            close()
        }
        drawPath(tail, color = Color(0xFF06121B), style = Stroke(span * .06f))
        drawPath(tail, color = accent)
    }
}

/** Static light rings: no frame observer, decorative timer, blur, or rotation. */
@Composable
internal fun AuroraHomePower2026(
    actionLabel: String,
    accent: Color,
    textColor: Color,
    dark: Boolean,
    busy: Boolean,
    diameter: Dp,
    onClick: () -> Unit,
) {
    Box(Modifier.size(diameter), contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            val radius = size.minDimension * .45f
            val center = Offset(size.width / 2f, size.height / 2f)
            drawCircle(
                brush = Brush.radialGradient(
                    listOf(accent.copy(alpha = .22f), accent.copy(alpha = .10f), Color.Transparent),
                    center = center, radius = radius * 1.14f,
                ),
                radius = radius * 1.14f, center = center,
            )
            drawCircle(accent.copy(alpha = .28f), radius, center, style = Stroke(1.dp.toPx()))
            drawCircle(accent.copy(alpha = .13f), radius * .96f, center, style = Stroke(10.dp.toPx()))
            drawCircle(accent, radius * .94f, center, style = Stroke(4.dp.toPx()))
        }
        Surface(
            onClick = onClick,
            enabled = !busy,
            color = Color.Transparent,
            shape = CircleShape,
            modifier = Modifier.size(diameter * .82f).testTag("home-connect")
                .semantics { contentDescription = actionLabel; role = Role.Button },
        ) {
            Box(
                Modifier.fillMaxSize().background(
                    Brush.radialGradient(
                        if (dark) listOf(Color(0xFF083843), Color(0xFF04131C))
                        else listOf(Color(0xFFE1FFFF), Color(0xFFF3FBFF)),
                    ),
                ),
                contentAlignment = Alignment.Center,
            ) {
                Column(
                    Modifier.padding(horizontal = 9.dp, vertical = 12.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Canvas(Modifier.size(43.dp)) {
                        val stroke = 5.dp.toPx()
                        drawArc(accent, -44f, 268f, false,
                            topLeft = Offset(stroke, stroke * 1.5f),
                            size = Size(size.width - stroke * 2, size.height - stroke * 2.3f),
                            style = Stroke(stroke, cap = StrokeCap.Round))
                        drawLine(accent, Offset(size.width / 2f, stroke * .4f),
                            Offset(size.width / 2f, size.height * .47f), strokeWidth = stroke, cap = StrokeCap.Round)
                    }
                    Spacer(Modifier.height(9.dp))
                    Text(actionLabel, color = textColor, fontSize = 15.sp,
                        fontWeight = FontWeight.Bold, textAlign = TextAlign.Center)
                }
            }
        }
    }
}

/** Small native card illustration for the separate game-room button. */
@Composable
internal fun AuroraHomeCards2026(modifier: Modifier = Modifier) {
    Box(modifier.size(52.dp), contentAlignment = Alignment.Center) {
        Surface(
            color = Color(0xFFF9F4FF), shape = RoundedCornerShape(5.dp),
            border = BorderStroke(1.dp, Color(0xFFD8D2EF)),
            modifier = Modifier.size(30.dp, 41.dp).rotate(-14f).align(Alignment.CenterStart),
        ) {
            Box(contentAlignment = Alignment.Center) {
                Text("♥", color = Color(0xFFE04C79), fontSize = 23.sp, fontWeight = FontWeight.Bold)
            }
        }
        Surface(
            color = Color.White, shape = RoundedCornerShape(5.dp),
            border = BorderStroke(1.dp, Color(0xFFD8D2EF)),
            modifier = Modifier.size(30.dp, 43.dp).rotate(5f).align(Alignment.CenterEnd),
        ) {
            Box(Modifier.padding(3.dp)) {
                Text("A", color = Color(0xFF5930AD), fontSize = 9.sp, fontWeight = FontWeight.Bold)
                Text("♠", color = Color(0xFF5930AD), fontSize = 23.sp, modifier = Modifier.align(Alignment.Center))
            }
        }
    }
}

@Composable
internal fun AuroraHomeGlobe2026(color: Color, modifier: Modifier = Modifier) {
    Canvas(modifier) {
        val stroke = 1.8.dp.toPx()
        val radius = size.minDimension * .44f
        val center = Offset(size.width / 2, size.height / 2)
        drawCircle(color, radius, center, style = Stroke(stroke))
        drawOval(color, Offset(center.x - radius * .46f, center.y - radius),
            Size(radius * .92f, radius * 2), style = Stroke(stroke))
        drawLine(color, Offset(center.x - radius, center.y), Offset(center.x + radius, center.y), stroke)
        drawOval(color, Offset(center.x - radius, center.y - radius * .42f),
            Size(radius * 2, radius * .84f), style = Stroke(stroke))
    }
}

@Composable
internal fun AuroraHomeShield2026(color: Color, connected: Boolean, modifier: Modifier = Modifier) {
    Canvas(modifier) {
        val shield = Path().apply {
            moveTo(size.width * .5f, size.height * .1f)
            lineTo(size.width * .83f, size.height * .25f)
            lineTo(size.width * .80f, size.height * .57f)
            cubicTo(size.width * .76f, size.height * .76f, size.width * .60f, size.height * .86f,
                size.width * .5f, size.height * .92f)
            cubicTo(size.width * .40f, size.height * .86f, size.width * .24f, size.height * .76f,
                size.width * .20f, size.height * .57f)
            lineTo(size.width * .17f, size.height * .25f)
            close()
        }
        drawPath(shield, color.copy(alpha = .13f))
        drawPath(shield, color, style = Stroke(2.dp.toPx(), cap = StrokeCap.Round))
        if (connected) {
            val tick = Path().apply {
                moveTo(size.width * .33f, size.height * .50f)
                lineTo(size.width * .46f, size.height * .63f)
                lineTo(size.width * .67f, size.height * .39f)
            }
            drawPath(tick, color, style = Stroke(2.3.dp.toPx(), cap = StrokeCap.Round))
        }
    }
}
