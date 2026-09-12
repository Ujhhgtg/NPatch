# UI review

Verified on an isolated Pixel 7 emulator, Android 17 / API 37, x86_64 with 16 KB pages. The connected physical device was not used. Twelve temporary APKs containing only module metadata supplied a repeatable long module list; no patch or installation operation was executed through NPatch.

| Scenario | Result | Evidence |
| --- | --- | --- |
| Real search input | A single tap focused the real text field, opened the keyboard, and accepted a package query. | `04-search-focused.png` |
| Home shortcuts and rapid root tab changes | Home → Modules selected the Modules page. Ten rapid alternating Home/Settings clicks settled on the requested Home page. Settings Back returned to Home. | `08-rapid-tabs-home.png`, `10-settings-back-home.png` |
| Module list and floating navigation | At the end of the list the complete final row ends at y=2063, above the floating bar at y=2148. The collapsed title/search/tabs have a readable surface. | `03-modules.png`, `05-modules-bottom.png` |
| Settings alignment and dialogs | Background image and card opacity titles share the same horizontal alignment. Theme, installer and DNS dialogs have proper insets; one system Back closes each dialog without leaving Settings. | `09-settings.png`, `12-theme-dialog.png`, `15-installer-dialog.png`, `16-dns-dialog.png` |
| Welcome review predictive back | Captured an actual edge-back gesture in progress. The outgoing destination is opaque; releasing the gesture returns to the previous Settings scroll position. | `19-welcome-predictive-back.png`, `20-welcome-return-settings.png` |
| About collapse | Both the title and Back button remain present after scrolling. | `21-about-collapsed.png` |
| Selection across rotation | Entered a search query, rotated to landscape and back, then selected the fixture. Query and result navigation survived; New Patch showed the chosen application. Landscape search and rows respect the display cutout. | `23-select-apps-landscape.png`, `24-select-restored.png`, `25-new-patch-config.png` |
| Embedded modules | Selected two modules and returned to configuration. Both names and count 2 were retained. | `30-embedded-return.png` |
| Keyboard and module confirmation | With the keyboard open, the final selection row ended at y=1265; the confirmation FAB occupied y=1328–1475, above the keyboard at y=1517. | `28-modules-ime.png`, `29-modules-ime-bottom.png` |
| Advanced options | Enabling the version code and target SDK overrides displayed editable values 1 and 28. | `31-patch-advanced-fields.png` |
| Dark theme and large text | At font scale 1.5, titles, metadata, switches and input fields remained readable and scrollable. The final module stayed above the floating bar. | `32-patch-dark-large-font.png`, `33-modules-dark-large-font.png`, `34-modules-dark-bottom.png` |

The emulator was returned to portrait, font scale 1.0 and light mode after the review. Build and instrumentation results are recorded separately by the main task; screenshots do not substitute for those checks. Actual module execution and APK patch/install behavior were outside this UI review.
