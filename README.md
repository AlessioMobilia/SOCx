# 🚀 SOCx – Simple OSINT Centralized eXtension

**SOCx** is the essential extension for security analysts, digital investigators, and **OSINT (Open-Source Intelligence)** enthusiasts. Designed to accelerate and centralize the verification of **IOC (Indicators of Compromise)**, SOCx allows you to perform in-depth checks directly from your browser in just a few clicks.

With integration of leading services like **VirusTotal**, **AbuseIPDB**, **NVD**, **Censys**, **Shodan**, **AlienVault**, **MxToolbox**, and many others, SOCx offers a powerful, convenient, and entirely **privacy-first** solution.

🔗 **Official Website**: [socx.alessiomobilia.com](http://socx.alessiomobilia.com/)

---

## 📥 Install SOCx

You can install SOCx directly from your browser’s official store:

- **Chrome Web Store**: https://chromewebstore.google.com/detail/socx/nanabcjeikkjaiabmlncionjliiobcaf
- **Firefox Add-ons**: https://addons.mozilla.org/it/firefox/addon/socx/
- **Microsoft Edge Add-ons**: https://microsoftedge.microsoft.com/addons/detail/socx/bghkcnheknfloofcbffhhlfaojknjkfp

---

## ✨ Key Features

- 🔍 **Instant IOC Check**
  Quickly analyze IPs, domains, URLs, hashes, emails, ASN, MAC addresses, CVE
  identifiers, and more. Detection validates IPv4 octets, keeps file names such
  as `invoice.pdf` out of the domain results, and recognises internationalised
  domains. Defanging preserves the original scheme and the case of URL paths,
  and refanging restores `[.]`, `(.)`, `{.}`, `[dot]`, `[:]`, `[at]`, `hxxp`,
  `hxxtp` and `meow` markers anywhere in the text.

- 📘 **Guided user workflow**
  A dedicated wiki with step‑by‑step examples, tips, and best practices for non‑technical users is available in the [SOCx wiki](https://github.com/AlessioMobilia/SOCx/wiki).

- 🌐 **Integration with over 30 OSINT services**
  Support for the most widely used services in the threat intelligence industry,
  including public lookups from Cisco Talos, URLhaus, Spamhaus, RIPEstat,
  Cloudflare Radar, ThreatMiner, Certificate Transparency, and CIRCL Hashlookup.

- 🛡️ **Privacy-first processing**
  SOCx does not run analytics or send investigation data to SOCx servers.
  Indicators, selected website content, and API keys are sent only when needed
  directly to the OSINT providers configured by the user.

- 🧾 **Compact threat-intelligence summaries**
  VirusTotal, AbuseIPDB and NVD results highlight high-confidence risk and positive
  signals without dumping raw responses. File aliases, digital signatures,
  WHOIS, certificate, network, and reporting details are capped to useful
  investigation context. CVE reports include CVSS, CWE, affected products,
  references, and CISA KEV remediation details when available. Clipboard copies defang active indicators by default;
  this behavior can be disabled from Extension Settings.

- 📋 **Formatted service-page capture**
  Supported IOC result pages expose a compact SOCx copy button that extracts
  only provider-specific, structured intelligence fields without changing the
  host layout. The button remains hidden on anti-bot checks, empty reports and
  pages that do not expose enough recognized data. The control follows the host
  page contrast and accent while remaining identifiable as SOCx. Selection
  buttons and service-page copy buttons can be enabled independently from
  Extension Settings. The audited provider/source matrix is documented in
  [`docs/SERVICE_PAGE_EXTRACTION.md`](docs/SERVICE_PAGE_EXTRACTION.md).

- ⚡ **Coordinated provider requests**
  Provider lookups share short queues, transient-error retries, request
  deduplication, and a response cache whose lifetime is configurable from
  Extension Settings (2 minutes to 4 hours, 2 minutes by default). Shortening
  the window expires the entries already stored, and the cache can be cleared
  at any time. NVD lookups work without credentials; an optional NVD API key
  can be saved to use the higher authenticated rate limit.

- 🪄 **Magic IOC in one tab group**
  The configured lookups open as background tabs so the page being read keeps
  the focus, and on Chrome and Edge they are collected in a tab group labelled
  with the indicator, ready to be collapsed or closed at once. Grouping can be
  turned off from Extension Settings and is skipped on Firefox, which has no
  equivalent API. Above five tabs the lookup asks for a confirmation on the
  page. Custom services are honoured from both the context menu and the
  floating button.

- 🧮 **Bulk check workflow**
  Files can be imported from the picker or dropped on the workspace (.txt,
  .csv, .log, .eml and other text formats) and are appended to the current
  list. A running check can be cancelled, failed lookups can be retried on
  their own, and every indicator carries a consolidated verdict — malicious,
  suspicious, clean, pending, error or not checked — used by the verdict
  filters and by the one-click copy of the flagged indicators.

- ✨ **Smart selection formatting**
  Selected EDR, SIEM, OSINT, JSON, CEF, logfmt, key/value, CSV, HTML table, and
  ARIA grid data can be normalized for copying. Partial table selections reuse
  real headers when available and otherwise use neutral column names. Generic
  dashboards are reconstructed from the rendered selection, including fields
  whose labels sit above their values, without copying hidden tooltips or
  internal widget state.

- 🧩 **Query packs for SIEM and EDR hunting**
  SOCx ships the [SOCx query packs](https://github.com/AlessioMobilia/socx-query-packs)
  catalogue preconfigured: 22 query languages, 14 packs and 139 ready to run
  templates for Defender XDR, Sentinel, Splunk, Google SecOps, CrowdStrike,
  Cortex XDR, Elastic, QRadar, FortiSIEM, Trend Vision One, SentinelOne and
  more. See [Query packs](#-query-packs) below.

- 🧠 **Clean and intuitive interface**
  Designed to be lightweight and immediate. No frills, just OSINT.

---

## 🧪 How to Use

Use SOCx mainly while you browse: select an IOC (IP, domain, URL, hash, email, ASN, MAC, CVE) on any page and use the **right-click menu** or **floating SOCx buttons** to open your favorite OSINT tools in one click. CVEs receive a dedicated NVD intelligence button. For long texts or lists, open the **popup** and use **Query workspace**, **Bulk IOC Check**, **Subnet tools**, or the **Field notes** side panel to organize and investigate indicators more efficiently.

This product uses data from the NVD API but is not endorsed or certified by the
NVD.

For a more complete, always up‑to‑date guide with examples, screenshots, and best practices, see the [SOCx wiki](https://github.com/AlessioMobilia/SOCx/wiki).

---

## 🧩 Query packs

Reputation tells you whether an indicator is bad. A query tells you whether your
estate ever touched it — usually the more urgent question, and one that costs no
API quota at all because generating a query is pure local text work.

SOCx reads **query packs**: small declarative files that turn a list of
indicators into the right query for a given platform, and that also carry
indicator‑free hunting playbooks. The companion repository
[**socx-query-packs**](https://github.com/AlessioMobilia/socx-query-packs) is
preconfigured as a default source.

### What ships by default

|                            |         |
| -------------------------- | ------- |
| Query languages (dialects) | **22**  |
| Packs                      | **14**  |
| Templates                  | **139** |

Defender XDR, Sentinel, Splunk, Google SecOps (Chronicle), CrowdStrike Falcon
LogScale and Event Search, Cortex XDR/XSIAM, Elastic, IBM QRadar, FortiSIEM,
Trend Vision One, SentinelOne, Rapid7 InsightIDR, Sumo Logic, Devo, Securonix,
ArcSight, NetWitness, Graylog, osquery/Sophos Live Discover, grep and
PowerShell.

### Two kinds, configured separately

- **IOC packs** are parameterised on a list of indicators. Each template maps
  every indicator type to the _right_ table, field and operator, because an IP
  and a hash never live in the same column.
- **Standard packs** need no indicator: encoded PowerShell, Office spawning a
  shell, password spraying, inbox forwarding rules, cleared event logs.

They are configured from separate source lists — several URLs each, on their own
tab in the settings — and both land in the same palette, tagged by kind. A pack
declares its own **groups and subgroups**, which drive the palette sections and
the context menu submenus.

Each source can be restricted to the **technologies you actually run**: pick
`KQL` and `SPL` and the packs written in the other twenty languages are never
downloaded. The catalogue index names the language of every file, so the
selection is applied before the download, not after it.

### Organising a large catalogue

A source URL may point at a single pack, at a catalogue index, or at an index
that only **links to other index files** — so a SOC can publish one link to its
analysts and still keep queries split per platform, per team or per customer.
Included files are followed recursively (HTTP or HTTPS only, capped in depth and
file count) and every file of the tree is part of the pinned content hash.

Beyond groups, a repository can declare **its own filter dimensions**: a pack or
an index adds `facets` (for example `customer`, `tenant`, `squad`) and tags its
templates — or whole pack files, from the index — with `labels`. Every declared
dimension becomes a filter in the palette and in the query workspace, which is
how an MSSP filters its catalogue down to one customer.

```jsonc
// index.json — a catalogue of catalogues
{
  "schema": "socx.packindex/v1",
  "facets": [{ "id": "customer", "label": "Customer" }],
  "includes": ["customers/acme/index.json", "customers/globex/index.json"],
  "packs": [
    {
      "id": "acme-defender",
      "kind": "ioc",
      "dialect": "kql",
      "path": "packs/acme-defender.json",
      "labels": { "customer": ["ACME"] }
    }
  ]
}
```

### Adding your own queries

The Query packs settings expose all three authoring paths in one place:

- import a `.json` query pack from a local file;
- paste a GitHub, GitLab (including self-hosted), gist or internal URL, over
  HTTPS or over the plain HTTP many internal servers still use — a clear-text
  source is marked **not encrypted** in the settings;
- create or edit a template directly in the SOCx rule builder.

SOCx rewrites `blob` links to their raw form automatically. Private repositories
are supported with a token; pin a source to a tag or a commit instead of a
branch when you want reproducibility.

### Using them: palette and context menu

The in-page palette never appears on its own. It opens only when you ask for it:

- the keyboard shortcut (`Ctrl+Shift+K` by default); the **Keyboard shortcuts**
  section of the settings lists every SOCx action available from the keyboard,
  shows its current binding and links to the browser page where combinations
  are reassigned. The query palette and **Smart format selection**
  (`Alt+Shift+F`) have defaults; workspace commands start disabled so nothing
  else is taken from the console you are on;
- the **Insert query** submenu inside editable fields or selected text.

The palette is not a long list to scroll: a filter bar narrows it down by
**favorites**, by **kind** (IOC or hunting), by **query language**, by
**category**, and by any custom dimension the repository declared. Search runs
over everything — name, description, group, tags, labels — _and over the query
itself_, so `DeviceNetworkEvents`, `src_ip` or `T1059` find the templates that
actually contain them; space separated terms all have to match. Star a query
with `Alt+F` or the ☆ next to its name and it is pinned to the top of the list
under **★ Favorites**, on every console, until you unstar it.

When no console is open, use **Query workspace** from the SOCx popup or from the
persistent `SOCx › Open query workspace…` page context menu. It accepts a mixed
IOC list, offers the same filters, favorites and deep search over every enabled
IOC and hunting template, lists them 25 to a page inside a scrolling column,
exposes template variables, shows uncovered IOC types and chunk warnings, and
copies the generated query. IOC-only context actions
remain hidden until text is selected, so an empty page menu stays compact.

Pick a template, fill in its variables, and the query is written **into the
search bar you were standing in** rather than opened in a new tab, so the
console keeps your session, filters and time picker. Insertion goes through the
one path React, CodeMirror and Monaco all recognise, and falls back to the
clipboard with a message when a field refuses it.

The palette carries its own **indicator field**, at the top of the preview
column: it opens prefilled with whatever was found, shows what was recognised
("3 indicators · 2 IP · 1 Domain"), and can be typed into or pasted over at any
time — the query below it re-renders as you edit.

Indicators come from your current selection, or from the Bulk Check workspace
when there is none. Each template maps every indicator type to its own field,
and by default SOCx merges them into **one query**: IPs are compared against the
IP column, domains against the URL column, hashes against the hash column, all
joined by the dialect's `or`. A **Single query / One per type** switch next to
the indicator list changes it, and the choice is remembered. A template SOCx
cannot merge safely — types read from different tables, or a body that is not
one field-to-list comparison — falls back to one query per type and says why.
Long lists are split into chunks and labelled, and quoting and escaping are
decided by the dialect, never by the pack. Hunting queries read no indicator, so
the indicator list disappears when one is selected.

### The rule builder

Queries written inside SOCx can be composed in a form with a live preview
against sample indicators, saved to a personal library — where they show up in
the palette next to the community packs — and exported as a valid pack file,
ready to be shared with the team or contributed back to the community
repository. The exported format is exactly what the repository's CI validates,
so a pack built in the extension passes unchanged. Packs can be imported back
for editing.

### Trust model

A pack is fetched over the network and produces text that gets pasted into a
production SIEM, so it is treated as untrusted data throughout: packs contain
**no executable content**, escaping strategies are identifiers resolved inside
the extension rather than code supplied by the pack, unknown fields are dropped,
every fetched file is pinned together with a SHA‑256 content hash and a changed
source is blocked until the analyst accepts it, ids are namespaced per source,
and console links never open by themselves. Sources are fetched over HTTPS or,
for the internal servers that still need it, plain HTTP — no other scheme — and
a clear-text source is labelled **not encrypted** wherever it is listed, because
its queries can be read and rewritten in transit. A catalogue index is authoritative
for its `verified` attestation: packs may omit the duplicate field, but an
explicit pack value that contradicts the index is rejected.

Writing your own pack files is documented in
[**Writing SOCx query pack JSON files**](docs/QUERY_PACK_FORMAT.md) — the
complete field reference, the template placeholder and filter syntax, the
dialect table, index catalogues, validation rules and worked examples.

Further format documentation lives in the pack repository:
[schema](https://github.com/AlessioMobilia/socx-query-packs/blob/main/docs/SCHEMA.md),
[template syntax](https://github.com/AlessioMobilia/socx-query-packs/blob/main/docs/TEMPLATE-SYNTAX.md),
[dialects](https://github.com/AlessioMobilia/socx-query-packs/blob/main/docs/DIALECTS.md),
[authoring](https://github.com/AlessioMobilia/socx-query-packs/blob/main/docs/AUTHORING.md).

---

## 🛠️ Development and release documentation

See the [SOCx 1.3.1 release notes](docs/RELEASE_NOTES_1.3.1.md) for the newest
fixes, the [1.3.0 notes](docs/RELEASE_NOTES_1.3.0.md) for HTTP repositories and
the pack format reference, the [1.2.0 notes](docs/RELEASE_NOTES_1.2.0.md) for the palette and
catalogue work, and the [1.1.0 notes](docs/RELEASE_NOTES_1.1.0.md) for the query
pack foundations, safety model and validation scope.

SOCx uses Node.js 22.13+ and pnpm 11.19.0. Install dependencies with the
version pinned in `package.json`:

```bash
git clone https://github.com/AlessioMobilia/socx.git
cd socx
corepack enable
corepack prepare pnpm@11.19.0 --activate
pnpm install
```

Run the complete static and production-build verification for Chrome, Edge,
and Firefox:

```bash
pnpm verify
```

Create the three ZIP archives ready for store validation:

```text
pnpm package
build/chrome-mv3-prod.zip
build/edge-mv3-prod.zip
build/firefox-prod.zip
```

See the detailed guides before changing or publishing a release:

- [Development, architecture, and cross-browser testing](docs/DEVELOPMENT.md)
- [Packaging and store publication runbook](docs/RELEASE.md)

---

## 🤝 Contributing

SOCx is an open-source project: contributions, ideas, and improvements are welcome!

1. Fork the repository
2. Create a branch for your feature/fix
3. Commit your changes
4. Submit a Pull Request

---

## 📄 License

Distributed under the **[MIT](LICENSE)** license.

---

## 💬 Contact

📧 [info@alessiomobilia.com](mailto:info@alessiomobilia.com)
🐛 Open an issue on GitHub

---

### 🔐 SOCx: Your OSINT ally in the browser — Secure, efficient, free.

---
