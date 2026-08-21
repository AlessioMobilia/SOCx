# SOCx development guide

## Supported browser targets

SOCx produces a dedicated artifact for each store. Do not upload one browser's
artifact to another store.

| Browser | Plasmo target | Manifest | Development output     | Production output       |
| ------- | ------------- | -------- | ---------------------- | ----------------------- |
| Chrome  | `chrome-mv3`  | V3       | `build/chrome-mv3-dev` | `build/chrome-mv3-prod` |
| Edge    | `edge-mv3`    | V3       | `build/edge-mv3-dev`   | `build/edge-mv3-prod`   |
| Firefox | `firefox`     | V2       | `build/firefox-dev`    | `build/firefox-prod`    |

Firefox intentionally remains on Manifest V2 because the existing AMO listing
uses that manifest version and extension ID
`{017bef1c-5ecb-4a2e-a111-244174e2d9d8}`. Treat a move to Firefox MV3 as a
separate migration: it changes background lifetime and AMO submission
requirements, so it must be tested and released deliberately.

## Prerequisites

- Git.
- Node.js 22.13 or newer. CI uses the latest Node.js 22 release.
- Corepack and pnpm 11.19.0, pinned by `packageManager` in `package.json`.
- Current stable Chrome, Edge, and Firefox installations for manual testing.

Set up the toolchain and install exactly what is in `pnpm-lock.yaml`:

```bash
corepack enable
corepack prepare pnpm@11.19.0 --activate
pnpm --version
pnpm install --frozen-lockfile
```

Use pnpm for this repository. The pnpm lockfile is the canonical dependency
lock and is also used by the publication workflow.

## Project layout

- `src/background`: lifecycle, context menus, and Plasmo message handlers.
- `src/contents`: scripts injected into web pages.
- `src/popup`: toolbar popup.
- `src/options`: API keys, services, and user preferences.
- `src/sidepanel`: Chrome/Edge side panel and Firefox sidebar UI.
- `src/tabs`: bulk and subnet tools opened as extension tabs.
- `src/utility`: IOC parsing, API clients, exports, storage, and UI helpers.
- `src/utility/query`: untrusted pack validation, source pinning, dialects,
  rendering, grouping, faceted filtering (`paletteFilters.ts`), starred queries
  (`favorites.ts`), language mini-guide metadata (`guides.ts`), expandable
  command details (`guideCommands.ts`), and its shared DOM view
  (`languageGuideView.ts`). `palette.ts` mounts the same query browser as an
  injected overlay or as the dedicated workspace, while `queryViewRequest.ts`
  owns the shared indicator summary and render-result mapping.
  `guides.test.ts` enforces one guide and one detailed command set for every
  dialect declared in `dialects.json`; it also audits the richer Splunk field
  and statistical-command reference.
- `scripts/validate-builds.mjs`: validates target manifests and referenced files.
- `scripts/publish-chrome.mjs`: Chrome Web Store V2 publisher with temporary V1
  compatibility.
- `scripts/publish-edge.mjs`: retrying and status-verified Edge publisher.
- `scripts/publish-firefox.mjs`: current `web-ext` listed-submission publisher.
- `.github/workflows/submit.yml`: tag-triggered publication workflow.

When adding a new Plasmo message handler, also add its name to
`src/messaging.d.ts`. Plasmo generates the same declarations in `.plasmo`
during a build, while the tracked declaration keeps standalone TypeScript
checks deterministic on a fresh checkout.

IOC provider pages use the shared `IOCServices` content script. URL parsing is
kept in `servicePageAdapters`, provider-specific field contracts in
`servicePageParsers`, report readiness/formatting in `servicePageIntel`, and the
isolated host-aware control in `serviceCopyButton`. Every page adapter must have
an explicit parser contract with recognized labels and a minimum useful result;
never fall back to headings, summaries or arbitrary visible text. Keep the
button fixed and inside Shadow DOM so host layouts and styles remain unaffected.
The current provider-by-provider audit and exact extraction sources are tracked
in [`SERVICE_PAGE_EXTRACTION.md`](SERVICE_PAGE_EXTRACTION.md).

Only add a page adapter when the destination URL identifies the investigated
IOC. Generic search pages and landing pages, currently Google and PhishTank,
remain context-menu-only because page-wide extraction would include unrelated
results. Custom lookup templates likewise cannot receive an automatic adapter
without an explicit hostname and extraction contract.

## Development commands

Run a browser-specific watcher:

```bash
pnpm dev:chrome
pnpm dev:edge
pnpm dev:firefox
```

The default `pnpm dev` command targets Chrome MV3. Keep the watcher running
while testing: it writes the unpacked development extension to the directory
shown in the table above.

### Chrome development build

From a PowerShell terminal in the repository root:

```powershell
corepack prepare pnpm@11.19.0 --activate
pnpm install --frozen-lockfile
pnpm dev:chrome
```

Then open `chrome://extensions`, enable **Developer mode**, choose **Load
unpacked**, and select the complete `build/chrome-mv3-dev` directory (not its
ZIP and not an individual file). If SOCx was already loaded, use its **Reload**
button or remove the old copy before loading the new directory.

After a source change, wait for the terminal to report a successful rebuild,
reload SOCx from `chrome://extensions`, and reload the web page under test.
Clicking the toolbar icon must open the popup. The SOCx root and Query workspace
entry appear on a normal `http://` or `https://` page even without a selection;
IOC actions appear only after selecting text. Browser-owned `chrome://` pages
remain unavailable to extension context menus.

Firefox receives the native `menus` permission through the Plasmo manifest
override. Its persistent background page reconciles menu registrations both at
startup and after installation or updates; Chrome and Edge retain the
`contextMenus` permission.

Load the generated directory:

- Chrome: open `chrome://extensions`, enable Developer mode, choose **Load
  unpacked**, and select `build/chrome-mv3-dev`.
- Edge: open `edge://extensions`, enable Developer mode, choose **Load
  unpacked**, and select `build/edge-mv3-dev`.
- Firefox: keep `pnpm dev:firefox` running, open
  `about:debugging#/runtime/this-firefox`, choose **Load Temporary Add-on**, and
  select `build/firefox-dev/manifest.json`. This temporary installation is
  removed when Firefox restarts.

Do not install `build/firefox-prod.zip` through `about:addons` as if it were a
released XPI. The ZIP is the AMO submission artifact and is unsigned; release
and beta Firefox require Mozilla signing for a persistent installation. For a
local unsigned test, use **Load Temporary Add-on** as described above. For the
final installable package, upload the ZIP to AMO and test the signed XPI that
AMO returns.

After changing a content script or manifest setting, reload both the extension
and the page being tested. Browser extensions cannot inject into browser-owned
pages such as `chrome://`, `edge://`, or `about:` pages.

## Build and verification commands

```bash
# Unit and DOM fixture tests
pnpm test

# TypeScript only
pnpm typecheck

# One production target
pnpm build:chrome
pnpm build:edge
pnpm build:firefox

# All production targets
pnpm build:stores

# Manifest and referenced-file validation after the builds
pnpm validate:builds

# Recommended local/CI verification
pnpm verify

# Optional release audit against a local socx-query-packs checkout
SOCX_QUERY_PACK_AUDIT_DIR=/path/to/socx-query-packs pnpm test

# Firefox AMO static lint (warnings are reported without failing the build)
pnpm dlx web-ext@10.6.0 lint --source-dir build/firefox-prod
```

`pnpm verify` runs formatter/enrichment regression tests, TypeScript, all three
production targets, and generated-manifest checks. The validator also rejects
bundles that leave runtime packages unresolved, which would otherwise produce
a blank popup or a background process that cannot create its context menus. A
successful build does not replace interactive browser testing.

The optional catalogue audit loads the current `index.json`, verifies every
declared pack with SOCx's own defensive parser, checks index metadata and
template counts, then renders every template against representative IOC values.
Run the catalogue repository's `node scripts/validate.mjs` as well: the two
validators cover the producer and consumer sides of the format.

The smart-formatting fixtures use Vitest with Happy DOM. When changing
selection parsing, add a fixture for both the newly supported markup and a
nearby case that must remain unmodified, such as URLs, timestamps, IPv6 values,
empty table cells, or clipped first/last rows.

### Smart-formatting architecture

The browser path is visual-first. The content script freezes an immutable
selection snapshot as soon as the Range changes, before hover tooltips,
virtualized rows, or other page mutations can alter it. The snapshot records
only selected, rendered text nodes together with their rectangles, styles, DOM
order, and conservative label signals.

`visualFormatting.ts` reconstructs field relationships rather than flattening
an ancestor's `textContent`. It supports:

- labels and values on the same visual row;
- labels placed above values;
- repeated unmarked vertical field blocks;
- repeated two-column CSS Grid/Flex rows without semantic label elements;
- multiple columns whose labels form a row above their values;
- multiline values ending at the next strong label.

Open Shadow DOM selections are resolved through composed ranges before the
ordinary document range is considered. This is required by component-heavy
pages such as VirusTotal, where the visible property table lives inside a
custom element. If geometry is unavailable, a conservative text fallback also
recognizes at least three alternating `label`/`value` lines without punctuation.

Product field markers are captured before the visual reconstruction. This
includes Splunk event tokens (`.key.level-*` with `.key-name` and `.t`
children), so inline log fields keep their key/value relationship even when
the browser exposes usable text geometry.

A value selected on its own can be enriched only from a nearby explicit label
(`label`, `dt`, `aria-labelledby`, a field marker, or a trailing colon).
Surrounding values are never pulled into the selection.

Native tables, ARIA grids, and explicitly marked product fields retain their
strong semantics. Their values are nevertheless read through the rendered-text
filter so CSS-hidden descendants, action controls, and semantic tooltips do not
leak into the clipboard. Attribute payloads such as `data-raw` and `data-json`
are never considered selected visual values.

The semantic fallback is tested as a matrix of recurring security-product
structures rather than a list of vendor selectors:

- native OSINT summary tables, including a section title spanning both columns;
- label/value grids with empty separator elements and multiline values;
- native and ARIA definition lists, including consecutive values and nested
  detail cards;
- atomic `aria-labelledby` groups, list items, outputs, and marked field values;
- native and ARIA event tables, including clipped rows and contextual headers;
- explicitly attributed fields used by SIEM event inspectors;
- structured text commonly copied from consoles: JSON and partial JSON, CEF,
  logfmt, TSV, and punctuated or alternating key/value lines.

A section title is not treated as a column schema when it is the only populated
header in a two-column table whose first column is a unique set of labels. Two
real populated headers still produce a Markdown table. Semantic extraction also
removes tooltip roots and action controls identified through role, test marker,
title, or accessible name before reading a value.

JSON is parsed in two stages. Valid objects and arrays are always parsed first
without changing whitespace inside string values. A separate conservative
recovery accepts recognizable property fragments: it can add a missing outer
object, close unfinished objects or arrays, remove trailing commas, decode
copied HTML whitespace entities, and normalize padded keys/values or `*,*`
comma markers. Recovery still ends in `JSON.parse`; broken strings, missing
values, mismatched delimiters, and property-like prose are not guessed.

Visual candidates must cover at least 70% of the selected rendered text. A
single horizontal field or explicit vertical label may be accepted at high
coverage; weak vertical inference requires a repeated pattern. When geometry
is available but no interpretation is sufficiently safe, SOCx returns the
frozen rendered text instead of parsing a wider ancestor. The older semantic
fallback remains only for environments that expose no usable text rectangles.

Any change to this pipeline must add positive and negative fixtures covering:

- same-row and stacked fields;
- repeated unmarked two-column grids and open Shadow DOM property tables;
- multi-column stacked fields and multiline values;
- a nearby heading/paragraph that must remain plain text;
- visible values accompanied by hidden or semantic tooltips;
- internal `data-raw`/`data-json` payloads containing fields such as `origin`
  or serialized HTML;
- mutation of the live page after the snapshot has been captured.
- valid JSON with significant string whitespace, partial JSON, and malformed
  property-like prose that must not be recovered.
- a genuine two-column event table that must not be collapsed into key/value
  fields;
- accessible detail groups plus definition lists containing badges, multiple
  values, tooltip roots, and action controls.

## Cross-browser manual test matrix

Run this matrix on all three browsers before a release:

1. Install the unpacked or temporary production build and confirm there are no
   manifest or background-console errors.
2. Open the popup, toggle the theme, clear history, and open Options.
3. Save VirusTotal and AbuseIPDB keys plus an optional NVD key, reopen Options,
   and confirm that storage persists. Also confirm that an NVD lookup works with
   the key left empty. Run the same lookup twice within two minutes and confirm the daily
   counter only increases for the first network request. Use **Clear cache** in
   Options and confirm the next lookup reaches the provider again.
4. Select an IP, domain, URL, hash, email, and CVE on an HTTPS page. Confirm
   the SOCx context menus and floating buttons appear and open the expected
   service URLs. A CVE must show the dedicated NVD API button and copy a report
   containing only fields returned by the API.
5. Test refang, defang, CVE copy, and key/value formatting. Include complete and
   partial selections in native HTML tables and ARIA grids: one cell, middle
   columns, multiple rows, empty cells, nested presentation wrappers, grouped
   headers, `colspan`, and `rowspan`. Tabular selections must remain Markdown
   tables with only the selected rows/columns and their corresponding real
   headers (or neutral `Column N` fallbacks). Also cover a two-column property
   table, marked SIEM key/value fields, CEF or logfmt text, URLs, timestamps,
   and IPv6. Also include horizontal fields, labels above values, a repeated
   unmarked CSS Grid such as Spur, an open Shadow DOM property table such as
   VirusTotal, multi-column stacked fields, multiline values, an open hover tooltip, and a widget with
   hidden tooltip or raw state. Confirm that only text intersecting the frozen
   rendered selection is copied. Confirm clipboard fallbacks work
   when the page Clipboard API is unavailable. The floating IOC result must copy
   the same single-entry report as Bulk Check's Copy formatted, without provider
   headings. Confirm the shared fallback and success/error feedback work from
   Bulk Check and both subnet tools. Toasts
   must remain readable on light/dark host pages, stay above SOCx overlays, and
   fit narrow popup viewports without inheriting host-page button styles. With
   the selection still active, press the default smart-format shortcut
   (`Ctrl+Shift+Period`), then reassign it from Options and verify the new
   combination.
   On Firefox, also verify that **Customize shortcuts** opens Manage Extension
   Shortcuts with SOCx highlighted and that `Ctrl+Shift+Comma` opens the query
   palette; `Ctrl+Shift+K` is reserved by Firefox for its Web Console. When
   upgrading from 1.4.1 or earlier, verify that only the old SOCx defaults are
   migrated and that disabled or customized bindings remain unchanged.
6. Run Bulk Check with valid keys, without keys, and with a mixed/duplicate IOC
   list. An IP-only list must preselect AbuseIPDB without VirusTotal; mixed lists
   must still select the providers needed by their other IOC types. Confirm errors
   remain per IOC and do not abort the queue. For VT files,
   verify capped aliases and valid/invalid/unsigned signature states; for
   domains verify compact WHOIS/certificate details; for AbuseIPDB verify capped
   hostnames, distinct reporters, TOR, whitelist, and every available proxy/VPN
   signal without an `Additional signals` placeholder. Copied results must use one
   aligned field list per provider, without provider or intermediate section
   headings; the per-IOC Copy action must match Copy formatted. Confirm that copied
   IOC fields are defanged by default, then disable
   **Sanitize copied intelligence** in Options and confirm they are copied in
   active form. In the right-hand summary, provider cards must show only their
   risk verdict/counts; contextual fields belong in the result text and the
   capped **Quick facts** list. Include lowercase and uppercase duplicate CVEs;
   confirm they normalize to one identifier, auto-select NVD, and expose CVSS,
   CWE, affected products, references, and CISA KEV fields only when present.
7. Test IPv4 and IPv6 subnet extraction, private subnets, invalid prefixes, the
   AbuseIPDB subnet flow, clipboard export, and spreadsheet export.
8. Open Field Notes from the popup. Chrome and Edge must open `sidePanel`;
   Firefox must open `sidebarAction`. Confirm notes persist after closing it.
9. Open VirusTotal, AbuseIPDB and a representative mix of supported static,
   SPA and raw-JSON IOC result pages. Confirm the SOCx copy pill adopts readable
   host-page contrast, stays clear of navigation, does not shift page layout,
   follows SPA URL changes, and copies a compact API-like report containing only
   the recognized fields for that provider. Empty reports, partial shells and
   anti-bot pages (including localized Cloudflare checks) must not receive a
   button. Toggle **Show IOC page copy buttons** and confirm all page-copy
   controls are removed or restored without affecting **Show selection
   buttons**. Verify the inverse combination as well. Pages without an IOC in
   their URL must not receive a button.
10. If file-URL support is part of the release, enable **Allow access to file
    URLs** in Chrome/Edge and test an explicit local HTML file. This user toggle
    cannot be enabled by the extension.
11. On a fresh profile, open Query workspace from the popup without selecting
    text. Paste a mixed IOC list, browse both IOC and standard templates, set
    variables and copy a rendered query. On a regular page, use
    `SOCx › Open query palette…` and confirm it opens the in-page palette rather
    than a workspace tab; repeat on a page that blocks content scripts and
    confirm Query workspace opens as the fallback. Confirm IOC-specific context
    actions remain selection-only.
12. Open the query palette and confirm the built-in sources populate
    automatically. Verify the catalogue count, platform matching,
    fuzzy search, keyboard navigation, insertion into a plain input and a
    React/Monaco/CodeMirror console, and clipboard fallback. Confirm Sentinel
    packs do not appear on unrelated Azure portal routes. Refresh a modified
    test source and verify its old cache remains active until **Accept change**.
    Test a private HTTPS source, disable/re-enable a source, and confirm two
    sources with the same pack id remain distinct. Add a plain `http://` source
    served from the local network and confirm it imports, that it is labelled
    **not encrypted** in the settings, and that an unreachable one reports the
    clear-text hint instead of a bare fetch error. Confirm index-level
    `verified` values are inherited when the pack omits the field, while an
    explicit mismatch is rejected. In Query packs settings, import a JSON pack,
    add a link and open the browser shortcut manager. In Rule builder, create an
    IOC template with variables and per-type bindings, preview it, export it,
    import it again, and confirm the variables survive the round trip. Filter
    the palette by favorites, kind, language, source pack, category and a
    repository declared facet. On a recognised console, confirm its pack filter
    is active on open. Switch between IOC and hunting templates and verify the
    grid tracks do not move, no horizontal scrollbar appears, and the query-list
    scrollbar uses the SOCx theme. Open the in-palette language guide, search
    for a command and follow an official-documentation link. Confirm a starred
    query survives a pack refresh and a browser restart. Search for a field name
    that only appears inside a query body, and
    for two space separated terms. Point a source at an index whose `includes`
    reference other index files and confirm every pack is imported once, that a
    duplicate pack id is refused, and that restricting the source to a couple of
    technologies re-imports it with the other languages left out. With the Query
    workspace tab left open in the background, change the technologies, enable
    or disable a source and save a personal template: the tab has to pick each
    change up on its own, without being reloaded.
13. Trigger Magic IOC with grouping enabled and disabled. On Chrome/Edge,
    confirm background tabs are adjacent, grouped, labelled and colour-stable;
    on Firefox confirm they open without grouping. Configure more than five
    destinations and verify cancelling the in-page confirmation opens none.

Use separate, low-privilege test API keys. Never add `.env` files, BPP keys, or
store credentials to Git.

## Cross-browser implementation notes

- Firefox supports the `chrome` namespace for compatibility, but its sidebar
  API is `sidebarAction`; Chromium uses the incompatible `sidePanel` API.
- Plasmo converts `host_permissions` into the Firefox MV2 `permissions` list.
  Host match patterns must not be added directly to Chrome/Edge MV3 API
  permissions.
- Background execution differs: Chrome/Edge MV3 use a service worker, while
  the current Firefox MV2 build uses a background script. Do not rely on
  in-memory background state surviving MV3 service-worker suspension.
- All API calls are made from the extension. Store privacy declarations must
  describe the IOC and API-key data sent directly to configured third-party
  services.
- `pnpm-workspace.yaml` pins reviewed transitive security updates and the
  install scripts required by Plasmo's native build tools. It also applies a
  narrow patch to Plasmo's Parcel resolver so relative imports resolve
  consistently on Windows. Keep that patch until the upstream resolver ships
  an equivalent fix and all three builds have been retested without it.
- The `targets.default.includeNodeModules` setting in `package.json` is
  required for store builds. Without it, this Plasmo/Parcel setup can emit
  extension entry points that still refer to Node package names; browsers
  cannot resolve them at runtime.

## Troubleshooting

If pnpm 11 reports `ERR_PNPM_IGNORED_BUILDS`, activate the repository's pinned
pnpm version and reinstall:

```bash
corepack prepare pnpm@11.19.0 --activate
pnpm install --frozen-lockfile
```

If messaging names become `never` during typechecking, ensure the handler name
exists in `src/messaging.d.ts`, then rebuild once to refresh `.plasmo`.

If a context menu is missing after an update, reload the extension so the
`runtime.onInstalled` setup runs again and inspect the background console.

If the popup is blank or every context menu is missing, first rebuild and load
the generated target directory rather than the repository root. In Chrome,
open the extension card's **Errors** or service-worker inspector and check for
`Cannot find module` errors. Run `pnpm verify`; its build validator fails when
a runtime dependency was accidentally left outside the generated bundles.

`pnpm audit --prod` covers packages shipped with the extension. A full
`pnpm audit` also includes Plasmo/Parcel build-only packages; review those
findings separately and never force a newer Parcel major/minor underneath the
version pinned by Plasmo.

## Primary references

- [Chrome extension manifest](https://developer.chrome.com/docs/extensions/reference/manifest)
- [Firefox WebExtensions compatibility](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Chrome_incompatibilities)
- [Firefox temporary installation](https://extensionworkshop.com/documentation/develop/temporary-installation-in-firefox/)
- [Firefox signing and distribution](https://extensionworkshop.com/documentation/publish/signing-and-distribution-overview/)
- [Microsoft Edge extension overview](https://learn.microsoft.com/en-us/microsoft-edge/extensions/)
