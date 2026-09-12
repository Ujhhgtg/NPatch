@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

// Adapted from WeKit: ui/content/WeKitBasicDialog.kt.
// Dialog spacing, surface and scrolling are copied from that implementation.
// NPatch keeps the dialog window alive until its exit transition has completed.
package top.nkbe.npatch.ui.component.m3

import androidx.activity.compose.PredictiveBackHandler
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.MutableTransitionState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.BasicAlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.navigationevent.compose.LocalNavigationEventDispatcherOwner
import androidx.navigationevent.findViewTreeNavigationEventDispatcherOwner
import kotlinx.coroutines.CancellationException

/** Always call this composable, passing [show]; do not wrap it in `if (show)`. */
@android.annotation.SuppressLint("ConfigurationScreenWidthHeight")
@Composable
fun SettingsDialog(
    show: Boolean,
    title: String,
    onDismissRequest: () -> Unit,
    dismissOnBackPress: Boolean = true,
    dismissOnClickOutside: Boolean = true,
    confirmButton: @Composable () -> Unit = {},
    dismissButton: @Composable () -> Unit = {
        TextButton(onClick = onDismissRequest) { Text(stringResource(android.R.string.cancel)) }
    },
    content: @Composable ColumnScope.() -> Unit,
) {
    val visibility = remember { MutableTransitionState(false) }
    var backProgress by remember { mutableFloatStateOf(0f) }
    LaunchedEffect(show) {
        if (show) backProgress = 0f
        visibility.targetState = show
    }
    if (!visibility.currentState && !visibility.targetState && visibility.isIdle) return

    val maxHeight = (LocalConfiguration.current.screenHeightDp * 0.9f).dp
    BasicAlertDialog(
        onDismissRequest = { if (show) onDismissRequest() },
        properties = DialogProperties(dismissOnBackPress = false, dismissOnClickOutside = dismissOnClickOutside),
    ) {
        // Miuix provides a dispatcher for its page stack. This is a separate window:
        // bind to its own dispatcher so closing a dialog cannot pop the page beneath it.
        // See InstallerX's WindowNavigationEventBridge usage; owning the window root lets
        // us bind directly, as recommended by that bridge's implementation.
        val windowView = LocalView.current
        val windowOwner = remember(windowView) {
            requireNotNull(windowView.findViewTreeNavigationEventDispatcherOwner()) {
                "A settings dialog must be hosted by its own navigation event dispatcher"
            }
        }
        CompositionLocalProvider(LocalNavigationEventDispatcherOwner provides windowOwner) {
            // Keep consuming back through the exit animation, including non-dismissible dialogs.
            PredictiveBackHandler(enabled = true) { events ->
                if (show && dismissOnBackPress) {
                    try {
                        events.collect { backProgress = it.progress }
                        onDismissRequest()
                    } catch (cancelled: CancellationException) {
                        backProgress = 0f
                        throw cancelled
                    }
                } else {
                    events.collect { }
                }
            }
            val animatedBack by animateFloatAsState(backProgress, spring(), label = "dialogBack")
            AnimatedVisibility(
                visibleState = visibility,
                enter = fadeIn() + scaleIn(initialScale = 0.92f),
                exit = fadeOut() + scaleOut(targetScale = 0.92f),
            ) {
                Surface(
                    modifier = Modifier
                        .widthIn(max = 560.dp)
                        .heightIn(max = maxHeight)
                        .graphicsLayer {
                            scaleX = 1f - animatedBack * 0.08f
                            scaleY = scaleX
                        },
                    shape = MaterialTheme.shapes.extraLarge,
                    color = MaterialTheme.colorScheme.surfaceContainerHigh,
                    tonalElevation = 6.dp,
                ) {
                    Column(Modifier.padding(24.dp)) {
                        Text(
                            title,
                            style = MaterialTheme.typography.headlineSmall,
                            modifier = Modifier.semantics { heading() },
                        )
                        Spacer(Modifier.height(16.dp))
                        Column(
                            Modifier.weight(1f, fill = false).verticalScroll(rememberScrollState()),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                            content = content,
                        )
                        Spacer(Modifier.height(24.dp))
                        FlowRow(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp, androidx.compose.ui.Alignment.End),
                        ) {
                            dismissButton()
                            confirmButton()
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun SettingsErrorText(text: String) {
    Text(
        text = text,
        color = MaterialTheme.colorScheme.error,
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
    )
}
