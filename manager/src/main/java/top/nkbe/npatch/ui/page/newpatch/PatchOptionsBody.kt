package top.nkbe.npatch.ui.page.newpatch

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import top.nkbe.npatch.R
import top.nkbe.npatch.share.Constants
import top.nkbe.npatch.ui.component.m3.BaseItemContainer
import top.nkbe.npatch.ui.component.m3.BaseWidget
import top.nkbe.npatch.ui.component.m3.RadioButtonWidget
import top.nkbe.npatch.ui.component.m3.SegmentedColumn
import top.nkbe.npatch.ui.component.m3.SwitchWidget
import top.nkbe.npatch.ui.component.settings.SettingsEditor
import top.nkbe.npatch.ui.viewmodel.NewPatchViewModel
import top.nkbe.npatch.ui.viewmodel.NewPatchViewModel.ViewAction

@Composable
fun ConfiguringFab() {
    val viewModel = viewModel<NewPatchViewModel>()
    val label = stringResource(R.string.patch_start)
    ExtendedFloatingActionButton(
        onClick = { viewModel.dispatch(ViewAction.SubmitPatch) },
        // Material 3 hides the animated text from semantics and uses the icon label.
        icon = { Icon(Icons.Outlined.AutoFixHigh, contentDescription = label) },
        text = { Text(label) },
    )
}

@Composable
fun sigBypassLvTitle(level: Int): String = stringResource(
    when (level) {
        0 -> R.string.patch_sigbypasslv0
        1 -> R.string.patch_sigbypasslv1
        2 -> R.string.patch_sigbypasslv2
        3 -> R.string.patch_sigbypasslv3
        else -> error("Invalid sigBypassLv: $level")
    }
)

@Composable
fun sigBypassLvDesc(level: Int): String = stringResource(
    when (level) {
        0 -> R.string.patch_sigbypasslv0_desc
        1 -> R.string.patch_sigbypasslv1_desc
        2 -> R.string.patch_sigbypasslv2_desc
        3 -> R.string.patch_sigbypasslv3_desc
        else -> error("Invalid sigBypassLv: $level")
    }
)

/**
 * The complete segmented settings layout and animated expandable items are reused from
 * WeKit ui/content/m3 (ported from InstallerX-Revived's Material 3 settings widgets).
 */
@Composable
fun PatchOptionsBody(modifier: Modifier, onAddEmbed: () -> Unit) {
    val viewModel = viewModel<NewPatchViewModel>()
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(bottom = 104.dp),
    ) {
        item(key = "app") {
            SegmentedColumn {
                item {
                    BaseWidget(
                        icon = Icons.Outlined.Android,
                        title = viewModel.patchApp.label,
                        titleStyle = MaterialTheme.typography.headlineSmall,
                        description = viewModel.patchApp.app.packageName,
                    )
                }
            }
        }
        item(key = "mode") {
            SegmentedColumn(
                title = stringResource(R.string.patch_mode),
                modifier = Modifier.selectableGroup(),
            ) {
                item(key = "local") {
                    RadioButtonWidget(
                        title = stringResource(R.string.patch_local),
                        description = stringResource(R.string.patch_local_desc),
                        icon = Icons.Outlined.Api,
                        selected = viewModel.useManager,
                        onSelect = { viewModel.setUseManager(true) },
                    )
                }
                item(key = "integrated") {
                    RadioButtonWidget(
                        title = stringResource(R.string.patch_integrated),
                        description = stringResource(R.string.patch_integrated_desc),
                        icon = Icons.Outlined.WorkOutline,
                        selected = !viewModel.useManager,
                        onSelect = { viewModel.setUseManager(false) },
                    )
                }
                item(key = "modules", animatedVisibility = !viewModel.useManager) {
                    BaseWidget(
                        icon = Icons.Outlined.Extension,
                        title = stringResource(R.string.patch_embed_modules),
                        description = viewModel.embeddedModules.takeIf { it.isNotEmpty() }
                            ?.joinToString { it.label },
                        onClick = onAddEmbed,
                    ) {
                        Text(viewModel.embeddedModules.size.toString())
                    }
                }
            }
        }
        if (viewModel.hasSubProcesses) {
            item(key = "subprocess") {
                SegmentedColumn {
                    item {
                        BaseWidget(
                            icon = Icons.Outlined.Info,
                            title = stringResource(R.string.patch_inject_dex),
                            description = pluralStringResource(
                                R.plurals.patch_subprocess_detected_hint,
                                viewModel.subProcessCount,
                                viewModel.subProcessCount,
                            ),
                        )
                    }
                }
            }
        }
        item(key = "advanced") {
            SegmentedColumn(title = stringResource(R.string.patch_advanced)) {
                item(key = "package") {
                    BaseItemContainer {
                        SettingsEditor(
                            label = stringResource(R.string.patch_new_package),
                            text = viewModel.newPackageName,
                            onValueChange = { viewModel.newPackageName = it },
                        )
                    }
                }
                item(key = "debuggable") {
                    SwitchWidget(
                        title = stringResource(R.string.patch_debuggable),
                        icon = Icons.Outlined.BugReport,
                        checked = viewModel.debuggable,
                        onCheckedChange = { viewModel.debuggable = it },
                    )
                }
                expandableItem(
                    expanded = viewModel.overrideVersionCode,
                    topContent = {
                        SwitchWidget(
                            title = stringResource(R.string.patch_override_version_code),
                            description = stringResource(R.string.patch_override_version_code_desc),
                            icon = Icons.Outlined.Layers,
                            checked = viewModel.overrideVersionCode,
                            onCheckedChange = { viewModel.overrideVersionCode = it },
                        )
                    },
                    bottomContent = {
                        BaseItemContainer {
                            SettingsEditor(
                                label = stringResource(R.string.patch_custom_version_code),
                                text = viewModel.overrideVersionCodeValue,
                                onValueChange = { value -> viewModel.overrideVersionCodeValue = value.filter { it in '0'..'9' } },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            )
                        }
                    },
                )
                expandableItem(
                    expanded = viewModel.overrideTargetSdk,
                    topContent = {
                        SwitchWidget(
                            title = stringResource(R.string.patch_override_target_sdk),
                            description = stringResource(R.string.patch_override_target_sdk_desc),
                            icon = Icons.Outlined.Android,
                            checked = viewModel.overrideTargetSdk,
                            onCheckedChange = { viewModel.overrideTargetSdk = it },
                        )
                    },
                    bottomContent = {
                        BaseItemContainer {
                            SettingsEditor(
                                label = stringResource(R.string.patch_custom_target_sdk),
                                text = viewModel.overrideTargetSdkValue,
                                onValueChange = { value -> viewModel.overrideTargetSdkValue = value.filter { it in '0'..'9' } },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            )
                        }
                    },
                )
                item(key = "provider") {
                    SwitchWidget(
                        title = stringResource(R.string.patch_inject_mt_provider),
                        description = stringResource(R.string.patch_inject_mt_provider_desc),
                        icon = Icons.Outlined.AddCard,
                        checked = viewModel.injectProvider,
                        onCheckedChange = { viewModel.injectProvider = it },
                    )
                }
                item(key = "dex") {
                    SwitchWidget(
                        title = stringResource(R.string.patch_inject_dex),
                        description = stringResource(R.string.patch_inject_dex_desc),
                        icon = Icons.Outlined.AccountTree,
                        checked = viewModel.injectDex,
                        onCheckedChange = { viewModel.injectDex = it },
                    )
                }
                item(key = "microg") {
                    SwitchWidget(
                        title = stringResource(R.string.patch_use_microg),
                        description = stringResource(R.string.patch_use_microg_desc),
                        icon = Icons.Outlined.CloudSync,
                        checked = viewModel.useMicroG,
                        onCheckedChange = { viewModel.useMicroG = it },
                    )
                }
                item(key = "log") {
                    SwitchWidget(
                        title = stringResource(R.string.patch_output_log_to_media),
                        description = stringResource(R.string.patch_output_log_to_media_desc),
                        icon = Icons.Outlined.Output,
                        checked = viewModel.outputLog,
                        onCheckedChange = { viewModel.outputLog = it },
                    )
                }
                item(key = "cleartext") {
                    SwitchWidget(
                        title = stringResource(R.string.patch_cleartext_traffic),
                        description = stringResource(R.string.patch_cleartext_traffic_desc),
                        icon = Icons.Outlined.Http,
                        checked = viewModel.usesCleartextTraffic,
                        onCheckedChange = { viewModel.usesCleartextTraffic = it },
                    )
                }
            }
        }
        item(key = "signature") {
            SegmentedColumn(
                title = stringResource(R.string.patch_sigbypass),
                modifier = Modifier.selectableGroup(),
            ) {
                for (level in Constants.SIGBYPASS_NONE..Constants.SIGBYPASS_EXTREME) {
                    item(key = level) {
                        RadioButtonWidget(
                            title = sigBypassLvTitle(level),
                            description = sigBypassLvDesc(level),
                            icon = Icons.Outlined.Security,
                            selected = viewModel.sigBypassLevel == level,
                            onSelect = { viewModel.sigBypassLevel = level },
                        )
                    }
                }
            }
        }
    }
}
