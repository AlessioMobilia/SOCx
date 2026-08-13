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
- Node.js 20 or newer. CI uses Node.js 20.
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

The default `pnpm dev` command targets Chrome MV3.

Load the generated directory:

- Chrome: open `chrome://extensions`, enable Developer mode, choose **Load
  unpacked**, and select `build/chrome-mv3-dev`.
- Edge: open `edge://extensions`, enable Developer mode, choose **Load
  unpacked**, and select `build/edge-mv3-dev`.
- Firefox: open `about:debugging#/runtime/this-firefox`, choose **Load Temporary
  Add-on**, and select `build/firefox-dev/manifest.json`.

After changing a content script or manifest setting, reload both the extension
and the page being tested. Browser extensions cannot inject into browser-owned
pages such as `chrome://`, `edge://`, or `about:` pages.

## Build and verification commands

```bash
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

`pnpm verify` runs TypeScript, builds all three production targets, and checks
the generated manifests. A successful build does not replace interactive
browser testing.

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
5. Test refang, defang, CVE copy, and key/value formatting. Confirm clipboard
   fallbacks work when the page Clipboard API is unavailable.
6. Run Bulk Check with valid keys, without keys, and with a mixed/duplicate IOC
   list. Confirm errors remain per IOC and do not abort the queue.
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

`pnpm audit --prod` covers packages shipped with the extension. A full
`pnpm audit` also includes Plasmo/Parcel build-only packages; review those
findings separately and never force a newer Parcel major/minor underneath the
version pinned by Plasmo.

## Primary references

- [Chrome extension manifest](https://developer.chrome.com/docs/extensions/reference/manifest)
- [Firefox WebExtensions compatibility](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Chrome_incompatibilities)
- [Microsoft Edge extension overview](https://learn.microsoft.com/en-us/microsoft-edge/extensions/)
