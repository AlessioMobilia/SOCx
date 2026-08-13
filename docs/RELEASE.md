# SOCx packaging and store publication runbook

This runbook covers Chrome Web Store, Microsoft Edge Add-ons, and Firefox AMO.
Store dashboards and policies change over time, so review the linked official
documentation before each release.

## Release invariants

- `package.json` is the single source of truth for the extension version.
- Every uploaded version must be higher than the version already in that store.
- Chrome and Edge receive Manifest V3 artifacts.
- The existing Firefox listing receives the Manifest V2 artifact with AMO ID
  `{017bef1c-5ecb-4a2e-a111-244174e2d9d8}`.
- `manifest.json` must be at the ZIP root.
- Store credentials exist only in store dashboards and the GitHub
  `SUBMIT_KEYS` secret. They must never be committed.

## 1. Pre-release checks

Start from the exact commit to release and a clean worktree:

```bash
git status --short
corepack prepare pnpm@11.19.0 --activate
pnpm install --frozen-lockfile
pnpm verify
pnpm dlx web-ext@10.6.0 lint --source-dir build/firefox-prod
```

Then complete the manual matrix in `docs/DEVELOPMENT.md` using all three
browsers. At minimum, test the popup, Options storage, context menus, floating
buttons, clipboard, Field Notes, Bulk Check, subnet tools, and one live request
per configured service.

Review `package.json` and each generated `manifest.json` for:

- the intended version, name, description, icons, and Firefox ID;
- only required permissions and host permissions;
- the correct background and panel/sidebar keys for that target;
- no secrets, development URLs, source maps, or remotely hosted executable
  code.

## 2. Create store packages

```bash
pnpm package
```

Expected artifacts:

| Store                  | Artifact                    |
| ---------------------- | --------------------------- |
| Chrome Web Store       | `build/chrome-mv3-prod.zip` |
| Microsoft Edge Add-ons | `build/edge-mv3-prod.zip`   |
| Firefox AMO            | `build/firefox-prod.zip`    |

Run the manifest validator again after packaging:

```bash
pnpm validate:builds
```

Inspect the archives before upload. The first entry does not have to be the
manifest, but `manifest.json` must be at the archive root:

```bash
tar -tf build/chrome-mv3-prod.zip
tar -tf build/edge-mv3-prod.zip
tar -tf build/firefox-prod.zip
```

## 3. Create Firefox reviewer source archive

SOCx is bundled and minified, so Firefox reviewers must be able to reproduce
the submitted binary. From the release commit:

```bash
mkdir -p dist
git archive --format=zip --output=dist/source.zip HEAD
```

On PowerShell, create `dist` with:

```powershell
New-Item -ItemType Directory -Force dist
git archive --format=zip --output=dist/source.zip HEAD
```

Upload `dist/source.zip` as the source archive when AMO requests it. In reviewer
notes, provide these exact reproducibility commands:

```text
Required: Node.js 20 and pnpm 11.19.0
corepack prepare pnpm@11.19.0 --activate
pnpm install --frozen-lockfile
pnpm package:firefox
Output: build/firefox-prod.zip
```

## 4. Manual publication

### Chrome Web Store

1. Open the Chrome Developer Dashboard and select the existing SOCx item.
2. Upload `build/chrome-mv3-prod.zip`.
3. Recheck the privacy form and justify every requested permission/host.
4. Update listing text, screenshots, support URL, and release notes if needed.
5. Submit for review; do not assume upload means publication.

Official guide: [Prepare your extension](https://developer.chrome.com/docs/webstore/prepare)
and [publish it](https://developer.chrome.com/docs/webstore/publish).

### Microsoft Edge Add-ons

1. Open Partner Center and select the existing SOCx extension.
2. Upload `build/edge-mv3-prod.zip`.
3. Complete permission justifications, privacy declarations, listing assets,
   and certification notes.
4. Submit the package and monitor its certification state.

Official guide: [Publish a Microsoft Edge extension](https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension).

### Firefox AMO

Before uploading, review Mozilla's data-collection declaration. SOCx can send
user-selected IOC/website content and API requests to third-party OSINT
services, so do not declare `required: ["none"]`. Decide the exact Mozilla
taxonomy with the product/privacy owner, keep the privacy policy and AMO form
consistent, then add the approved `browser_specific_settings.gecko.data_collection_permissions`
entry. Until this is approved, `web-ext lint` reports one expected warning.

1. Open the existing SOCx listing in the AMO Developer Hub.
2. Upload `build/firefox-prod.zip`; AMO signs the accepted extension.
3. Upload `dist/source.zip` when prompted and include the reproducibility notes
   above.
4. Confirm the extension ID and compatibility range before submission.
5. Download and smoke-test the signed XPI when it becomes available.

Official guides: [Submit an add-on](https://extensionworkshop.com/documentation/publish/submitting-an-add-on/)
[package/sign with web-ext](https://extensionworkshop.com/documentation/develop/getting-started-with-web-ext/),
and [Firefox data-collection consent](https://extensionworkshop.com/documentation/develop/firefox-builtin-data-consent/).

## 5. Automated publication from GitHub Actions

`.github/workflows/submit.yml` runs only for a manually dispatched workflow or
a pushed `v*` tag. It builds each browser separately, validates TypeScript and
manifests, creates the Firefox source archive, and invokes Plasmo BPP 3.8.0.

Create the GitHub `SUBMIT_KEYS` secret from
`configs/bpp.keys.example.json`. Replace every `REPLACE_ME` value locally and
store the whole JSON object as the secret; do not commit the populated file.

Before enabling automated publication, verify:

- Chrome `extId`, OAuth client ID/secret, and refresh token;
- Firefox `extId`, API key, and API secret;
- Edge Partner Center product ID, client ID, and API key;
- that the first store submission already exists and accepts API updates.

The workflow publishes externally. Creating or pushing a release tag is
therefore a deliberate release action, not a build/test step.

## 6. Post-submission checklist

- Record each store's submission ID, status, and reviewer feedback.
- Compare the published version and permissions with the intended manifest.
- Install the store-delivered build in a clean browser profile and repeat a
  smoke test.
- Confirm the privacy-policy and support links are reachable.
- Do not delete the previous known-good local artifacts until all three stores
  have approved the release.

If one store rejects the package, fix the cause, increment the version, rebuild
all target artifacts, and retest. Never reuse a version number already uploaded
to a store.
