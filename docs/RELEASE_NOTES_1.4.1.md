# SOCx 1.4.1

This patch restores keyboard commands and shortcut management on Firefox.

## Firefox command execution

The Firefox package uses Manifest V2, where the compatibility `chrome.*`
namespace exposes asynchronous APIs through callbacks. The command handler was
awaiting the Promise returned by Chromium Manifest V3 instead, so it stopped
before finding the active tab.

SOCx now uses the tab supplied directly by Firefox's command event and a shared
callback bridge as a fallback. Query palette and smart-format commands therefore
reach the active page on Firefox as well as Chrome and Edge.

## Shortcut management

The Options button now calls Firefox's dedicated
`commands.openShortcutSettings()` API. It opens **Manage Extension Shortcuts**
with SOCx highlighted, instead of trying to create a privileged `about:addons`
tab through Chromium's Promise flow. The displayed bindings refresh when the
Options page regains focus.

The query palette default is now **Alt+Shift+Q** on Windows and Linux because
Firefox reserves `Ctrl+Shift+K` for its Web Console. Smart formatting remains
**Alt+Shift+F**. Existing user assignments remain browser-managed and can be
changed from the same native shortcut editor.

## Validation

Tests cover Firefox-style callback results, runtime errors, the tab passed by a
command event, the callback fallback and routing to Firefox's native shortcut
manager. Type checking and all browser packages are validated before release.
