# SOCx 1.5.3

This patch fixes the colour scheme of the Query workspace when SOCx dark mode
is enabled.

## Query workspace dark mode

The shared query browser now recognises the theme class applied to the page
body. Its template list, indicator editor, preview, filters and language guide
therefore use the same dark palette as the surrounding workspace instead of
falling back to light colours when the operating-system theme differs from the
saved SOCx preference.

Regression coverage verifies the text and control colours used by an embedded
workspace whose dark-mode preference is stored on the body.

## Validation

The tracked test suite, type checking, Chrome and Edge Manifest V3 packaging,
Firefox Manifest V2 packaging and manifest/runtime validation pass before
release.
