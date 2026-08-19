# SOCx 1.1.0

SOCx 1.1.0 adds local query generation, safer multi-tab investigations, a more
controllable Bulk Check workflow, configurable API caching, and stricter IOC
normalisation.

## Query packs and rule builder

The query palette loads the two built-in SOCx community sources on first use.
It matches packs to the current SIEM/EDR console, searches names, groups, tags
and descriptions, renders one escaped query per supported IOC type, and splits
long lists according to the dialect limits. The current selection has priority;
when it has no IOC, the Bulk Check workspace is used.

`Ctrl+Shift+K` opens the palette. Its current binding is visible in Query packs
settings, with a direct route to the browser's shortcut manager. The persistent
SOCx page context menu and the popup open a standalone **Query workspace** that
accepts IOC lists and browses every enabled query without requiring an open
console. IOC-specific actions still appear only when text is selected.

Query packs settings now make all custom-query paths explicit: import a pack
file, add an HTTPS/GitHub/GitLab source, or create a query directly in the Rule
builder. The builder previews, stores, edits, imports and exports personal
templates. Variables and per-indicator table, field and operator bindings
survive import/export.

Remote packs are data, never executable code. Sources must use HTTPS. SOCx
validates their schema and index metadata, drops unknown fields, resolves only
built-in escaping/filter identifiers, limits URL regular expressions, keeps ids
separate by source, and pins the index plus every fetched pack with one SHA-256
digest. A changed source does not replace the accepted cache until the analyst
explicitly accepts it.

The catalogue index owns the verification attestation. A pack that omits the
duplicate `verified` field inherits the index value; an explicit contradictory
value is still rejected. This fixes false failures for `defender-xdr-standard`
and `defender-xdr-ioc`.

## Magic IOC tab groups

Magic IOC now opens configured built-in and custom services as inactive tabs
next to the page that launched the lookup. Chrome and Edge group and label those
tabs; Firefox opens the same tabs without grouping. Grouping is optional. More
than five destinations require an in-page confirmation, and failure to show the
confirmation opens no tabs.

## Bulk Check

Text files can be selected or dropped onto the workspace and are appended
without losing existing indicators. A running queue can be cancelled without
leaving undispatched rows pending, and failed IOC lookups can be retried without
discarding successful results. VirusTotal receives only supported IOC types.

Every row now has one consolidated verdict used consistently by filters and the
**Copy flagged** action. A positive detection stays actionable even if another
provider fails; the failed provider remains visible and retryable. Missing API
keys are reported per provider instead of aborting unrelated services.

## IOC handling and cache

IPv4 octets are range-checked, common defang markers are restored without
lowercasing case-sensitive URL paths, unrelated Windows backslash paths remain
unchanged, known file names are not misclassified as domains, and IDN domains
are supported. IOC history moves a repeated lookup back to the most-recent
position.

The provider response cache can be set from 2 minutes to 4 hours. Reducing the
window immediately shortens entries already stored, and clearing the cache
invalidates in-flight writes as well as persisted responses.

## Validation performed

- Unit and DOM regression suite, including IOC parsing, request coordination,
  Bulk Check verdicts, tab grouping, query validation, workspace launch and
  rendering.
- TypeScript checks and production builds for Chrome MV3, Edge MV3 and Firefox
  MV2.
- Generated manifest and bundle validation.
- Firefox `web-ext` static lint.
- Producer and consumer validation of the community catalogue: 22 dialects,
  14 packs and 139 templates.

The interactive browser matrix remains documented in
[`DEVELOPMENT.md`](DEVELOPMENT.md); store-delivered builds should receive a final
smoke test after signing/review.
