# Material 3 Expressive UI

The manager UI uses only WeKit and InstallerX-Revived as design references. Business operations remain NPatch's. The copied components retain their upstream copyright and license headers; adaptations use the repository's GPL license.

Reference working copies used on 2026-09-12:

- WeKit: `650febaa3717eddd39f5f29a4dfa6dfd37875cb1`
- InstallerX-Revived: `f6ffcd8ea84e629bc14160414e7343f07a4d3d76`

Paths in the following table are relative to each reference project's `app/src/main/java`. Destination paths are under `manager/src/main/java/top/nkbe/npatch/ui`.

| Source | Destination / adaptation |
| --- | --- |
| WeKit `dev/ujhhgtg/wekit/ui/content/m3/ExpressiveCollapsingTopAppBar.kt` | `component/ExpressiveCollapsingTopAppBar.kt`; complete title layout, measurement, drag, typography interpolation and heading semantics copied. |
| WeKit `ui/content/m3/ExpressiveBackButton.kt` | `component/ExpressiveBackButton.kt`; NPatch's existing Material arrow and localized back description. |
| WeKit `ui/content/m3/{SegmentedColumn,BaseWidget,BaseItemContainer,SwitchWidget,RadioButtonWidget,M3Shape}.kt` | `component/m3/`; complete grouped item shapes, animations and widgets. Ordinary actions do not expose selection; switches and radio rows have one accessible state. |
| WeKit `ui/content/WeKitBasicDialog.kt` | `component/m3/SettingsDialog.kt`; surface, 24 dp spacing, scrollable content. Retains the window during exit and binds predictive back to its own window dispatcher. |
| WeKit `ui/content/M3Blur.kt` | `component/M3Blur.kt`; complete M3 color/blend and backdrop helpers copied. The reference tint is composited on the regular canvas to keep the title legible when a capture frame is unavailable. |
| WeKit `ui/content/FloatingBottomBar.kt`, `ui/content/{animation,liquid}/*.kt`, `ui/content/DragGestureInspector.kt` | `component/`; complete floating navigation, gestures, highlights and blur implementation copied, including keyboard and accessibility actions. |
| WeKit `ui/navigation/M3NavEffects.kt`, `ui/utils/CornerRadiusUtil.kt` | `page/M3NavEffects.kt`, `util/CornerRadiusUtil.kt`; device corner clipping, dimming and surface colors. |
| WeKit `activity/settings/SettingsActivity.kt` | `activity/MainActivity.kt`; Miuix NavDisplay, persisted typed back stack and per-entry lifecycle/viewmodel ownership. |
| WeKit `ui/utils/theme/{ModuleAppTheme,SeedResolver}.kt` | `theme/Theme.kt`; MaterialExpressiveTheme, expressive motion and MaterialKolor seed generation. |
| InstallerX `com/rosan/installer/ui/navigation/PagerState.kt` | `page/MainPagerState.kt`; complete cancelable navigation controller shared by Main and Manage. |
| InstallerX `ui/page/main/settings/home/HomePage.kt` | `page/HomeScreen.kt`; status panel, copied StatCard and grouped device information. |
| InstallerX `ui/page/main/settings/preferred/about/AboutPage.kt` | `page/AboutScreen.kt`; collapsing heading, grouped links and app information. |
| InstallerX `ui/theme/Shape.kt` | `component/m3/AppItemShapes.kt`; complete first/middle/last/single list shapes copied. |
| InstallerX `ui/page/main/widget/setting/NavigationItemWidget.kt` | `page/SettingsScreen.kt`; shared settings action / chevron layout. |
| WeKit `ui/agent/settings/PromptsScreen.kt` | `page/ManageScreen.kt`; PrimaryTabRow and one retained pager. |
| InstallerX `ui/page/main/settings/config/apply/{ApplyPage,ApplyItemWidget}.kt` | `component/{SearchBar,AppItem}.kt`; real text input and app selection rows. |
| InstallerX `ui/page/main/installer/dialog/inner/{InstallingDialog,PreparingDialog}.kt` / Material 3 pull-to-refresh | `page/newpatch/DoPatchBody.kt`, `component/{LoadingDialog,NPatchPullToRefresh}.kt`; wavy progress and expressive loading indicators. |

## Design-system boundary

All text, buttons, cards, selection controls, tabs, menus, preferences and dialogs are Material 3. Material 3 is explicitly pinned to `1.5.0-alpha28`, matching WeKit, because the expressive APIs are not supplied by the BOM's stable Material version.

Direct Miuix dependencies are restricted to `miuix-nav-android`, `miuix-blur-android` and the shader module needed by blur. No Miuix UI, preference, icon or theme component library is used. COUI, Haze and the former Kyant backdrop dependency are removed.

## State and layout rules

- Each destination draws an opaque base and its own optional wallpaper before content. Navigation transitions cannot expose another destination through the foreground surface.
- One controller owns each PagerState. Clicks, shortcuts and Back submit a target; settled swipes report their result. Main keeps all three page compositions alive.
- DataStore theme values are loaded once at the activity boundary. Preferences consume the loaded state, without rendering placeholder defaults on tab entry.
- Scaffold measures the bottom navigation. Pages receive its actual height as scrollable end padding, keeping content behind blur while allowing the final item to scroll fully above navigation.
- Process recreation returns interrupted native patch/picker flows to a stable destination; configuration changes preserve their live state and pending result channels.
- Search uses one real input and one result tree. There is no fake input, IME-height focus reset, duplicate pager, or full-page visibility switch.
- InstallerX’s `adjustResize` activity behavior and patch-page IME padding keep inline editing from panning the entire destination.
- Dialog callers stay composed with `show = false` until exit completes. Nullable patch-dialog data is retained for that transition.

## Regression checks

`manager/src/androidTest` contains focused tests for ordinary action semantics, single switch/radio state nodes, and retained dialog exit. Run on an explicitly selected test emulator:

```sh
ANDROID_HOME=/path/to/android-sdk ./gradlew :manager:assembleDebug :manager:assembleDebugAndroidTest
adb -s emulator-5580 install -r manager/build/outputs/apk/debug/manager-debug.apk
adb -s emulator-5580 install -r manager/build/outputs/apk/androidTest/debug/manager-debug-androidTest.apk
adb -s emulator-5580 shell am instrument -w top.nkbe.npatch.test/androidx.test.runner.AndroidJUnitRunner
```

Runtime review should cover first-run and review-mode welcome, all main tabs, search focus/IME dismissal, selection, menu actions, dialog buttons and predictive back, app shortcuts, custom backgrounds, light/dark themes, large fonts, and last-item clearance beneath both navigation modes.
