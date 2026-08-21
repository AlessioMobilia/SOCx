# SOCx 1.4.2

This patch improves smart formatting for Splunk event logs and corrects the
default-shortcut migration introduced for Firefox in 1.4.1.

## Splunk event formatting

Smart formatting now recognizes Splunk event tokens rendered as nested
`.key.level-*`, `.key-name` and `.t` elements. Their field names and values are
captured before generic visual reconstruction, so inline log selections are
copied as aligned key/value text even when the browser exposes usable text
geometry.

Detection remains deliberately specific to Splunk's event structure. Generic
pages that happen to use `key-name` or `t` classes are left unchanged.

## Firefox shortcut migration

The query palette and smart-format defaults are consistently declared as
**Ctrl+Shift+Comma** and **Ctrl+Shift+Period** on all supported browsers.
Firefox upgrades migrate only shortcuts that exactly match defaults shipped by
SOCx 1.4.1 or earlier. Disabled commands and user-customized combinations stay
untouched.

Firefox now reads and opens shortcut settings through the Promise-based
`browser.commands` API, while Chromium continues to use its callback-based
extension API.

## Validation

Regression tests cover rendered Splunk selections, nearby non-Splunk markup,
legacy Firefox defaults, disabled commands and custom bindings. The complete
346-test suite, type checking, and the Chrome, Edge and Firefox package and
manifest validation pass before release.
