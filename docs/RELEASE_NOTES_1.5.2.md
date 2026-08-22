# SOCx 1.5.2

This patch fixes smart formatting for Microsoft Sentinel and Microsoft Entra
ID user-information panels.

## Azure user information

Explicit label/value associations inside the selected content now retain their
semantic priority even when the browser provides rendered text geometry. This
supports sparse Azure panels where many fields are empty or expose only an
action control, a layout that previously fell below the visual formatter's
coverage threshold.

Semantic pairs are checked against the visible selection snapshot before they
are accepted. Hidden tooltips and unselected ancestor content therefore remain
excluded.

The plain-text fallback also no longer interprets the colon in a clock value,
such as `20:56`, as a key/value separator.

## Privacy-safe regression coverage

Tracked regression fixtures cover rendered Entra ID identity properties and
Sentinel sign-in user information with sparse values. They use only synthetic
account identifiers, zero-based UUIDs and the reserved `example.test` domain;
no supplied HTML, personal data, customer names, tenant identifiers or secrets
are included.

## Validation

The tracked test suite, type checking, Chrome and Edge Manifest V3 packaging,
Firefox Manifest V2 packaging, manifest/runtime validation and Firefox linting
pass before release.
