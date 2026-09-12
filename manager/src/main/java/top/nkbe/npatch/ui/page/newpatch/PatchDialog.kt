package top.nkbe.npatch.ui.page.newpatch

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember

private class DialogSnapshot<T>(var value: T?)

/** Keeps the last dialog data available while SettingsDialog plays its exit transition. */
@Composable
fun <T : Any> RetainedPatchDialog(value: T?, content: @Composable (T, Boolean) -> Unit) {
    val snapshot = remember { DialogSnapshot(value) }
    if (value != null) snapshot.value = value
    snapshot.value?.let { content(it, value != null) }
}
