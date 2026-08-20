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
  (`favorites.ts`), palette insertion, and the personal rule builder.
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
   and IPv6. Confirm clipboard fallbacks work
   when the page Clipboard API is unavailable. The floating IOC result must copy
   the same single-entry report as Bulk Check's Copy formatted, without provider
   headings. Confirm the shared fallback and success/error feedback work from
   Bulk Check and both subnet tools. Toasts
   must remain readable on light/dark host pages, stay above SOCx overlays, and
   fit narrow popup viewports without inheriting host-page button styles.
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
11. On a fresh profile, open Query workspace from both the popup and a page
    context menu without selecting text. Paste a mixed IOC list, browse both IOC
    and standard templates, set variables and copy a rendered query. Confirm
    IOC-specific context actions remain selection-only.
12. Open the query palette and confirm the built-in sources populate
    automatically. Verify the catalogue count, platform matching,
    fuzzy search, keyboard navigation, insertion into a plain input and a
    React/Monaco/CodeMirror console, and clipboard fallback. Confirm Sentinel
    packs do not appear on unrelated Azure portal routes. Refresh a modified
    test source and verify its old cache remains active until **Accept change**.
    Test a private HTTPS source, disable/re-enable a source, and confirm two
    sources with the same pack id remain distinct. Confirm index-level
    `verified` values are inherited when the pack omits the field, while an
    explicit mismatch is rejected. In Query packs settings, import a JSON pack,
    add a link and open the browser shortcut manager. In Rule builder, create an
    IOC template with variables and per-type bindings, preview it, export it,
    import it again, and confirm the variables survive the round trip. Filter
    the palette by favorites, kind, language, category and a repository declared
    facet, and confirm a starred query survives a pack refresh and a browser
    restart. Search for a field name that only appears inside a query body, and
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
