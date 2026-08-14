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
Clicking the toolbar icon must open the popup. The SOCx context menu is
selection-only: select text on a normal `http://` or `https://` page, then
right-click the selection. It is intentionally unavailable on `chrome://`
pages.

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

# Firefox AMO static lint (warnings are reported without failing the build)
pnpm dlx web-ext@10.6.0 lint --source-dir build/firefox-prod
```

`pnpm verify` runs formatter/enrichment regression tests, TypeScript, all three
production targets, and generated-manifest checks. The validator also rejects
bundles that leave runtime packages unresolved, which would otherwise produce
a blank popup or a background process that cannot create its context menus. A
successful build does not replace interactive browser testing.

The smart-formatting fixtures use Vitest with Happy DOM. When changing
selection parsing, add a fixture for both the newly supported markup and a
nearby case that must remain unmodified, such as URLs, timestamps, IPv6 values,
empty table cells, or clipped first/last rows.

## Cross-browser manual test matrix

Run this matrix on all three browsers before a release:

1. Install the unpacked or temporary production build and confirm there are no
   manifest or background-console errors.
2. Open the popup, toggle the theme, clear history, and open Options.
3. Save VirusTotal and AbuseIPDB keys, reopen Options, and confirm that storage
   persists.
4. Select an IP, domain, URL, hash, email, and CVE on an HTTPS page. Confirm
   the SOCx context menus and floating buttons appear and open the expected
   service URLs.
5. Test refang, defang, CVE copy, and key/value formatting. Include an EDR/SIEM
   grid selected with and without its header, a two-column property table, CEF
   or logfmt text, URLs, timestamps, and IPv6. Confirm clipboard fallbacks work
   when the page Clipboard API is unavailable.
6. Run Bulk Check with valid keys, without keys, and with a mixed/duplicate IOC
   list. Confirm errors remain per IOC and do not abort the queue. For VT files,
   verify capped aliases and valid/invalid/unsigned signature states; for
   domains verify compact WHOIS/certificate details; for AbuseIPDB verify capped
   hostnames, distinct reporters, TOR, and whitelist signals. Copied results
   must use one aligned field list per provider, without intermediate section
   headings. Confirm that copied IOC fields are defanged by default, then disable
   **Sanitize copied intelligence** in Options and confirm they are copied in
   active form. In the right-hand summary, provider cards must show only their
   risk verdict/counts; contextual fields belong in the result text and the
   capped **Quick facts** list.
7. Test IPv4 and IPv6 subnet extraction, private subnets, invalid prefixes, the
   AbuseIPDB subnet flow, clipboard export, and spreadsheet export.
8. Open Field Notes from the popup. Chrome and Edge must open `sidePanel`;
   Firefox must open `sidebarAction`. Confirm notes persist after closing it.
9. Open an AbuseIPDB check page and confirm the site-specific content script
   loads without altering unrelated pages.
10. If file-URL support is part of the release, enable **Allow access to file
    URLs** in Chrome/Edge and test an explicit local HTML file. This user toggle
    cannot be enabled by the extension.

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
