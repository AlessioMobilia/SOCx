# Writing SOCx query pack JSON files

A **query pack** is a small JSON file that teaches SOCx how to turn a list of
indicators into a query for one platform — Defender XDR, Splunk, Google SecOps,
Elastic, QRadar, grep — and how to carry indicator‑free hunting queries next to
them.

Packs are pure data. They never contain code: quoting, escaping, list building,
chunking and length limits are decided by the **dialect** implemented inside the
extension, so a template author writes plain query text and cannot get the
escaping wrong. Anything a pack declares that the extension does not understand
is dropped at parse time.

This document is the authoritative, code‑derived reference for the file format.
The implementation lives in:

- [`src/utility/query/packSchema.ts`](../src/utility/query/packSchema.ts) — the model and the validator
- [`src/utility/query/render.ts`](../src/utility/query/render.ts) — the rendering engine
- [`src/utility/query/dialects.json`](../src/utility/query/dialects.json) — the bundled query languages
- [`src/utility/query/registry.ts`](../src/utility/query/registry.ts) — how sources and indexes are fetched

---

## Table of contents

1. [The three file types](#1-the-three-file-types)
2. [Quick start](#2-quick-start)
3. [Pack reference](#3-pack-reference)
4. [Templates](#4-templates)
5. [Indicator bindings (`byType`)](#5-indicator-bindings-bytype)
6. [The template body language](#6-the-template-body-language)
7. [What the renderer does for you](#7-what-the-renderer-does-for-you)
8. [Merged multi-type queries](#8-merged-multi-type-queries)
9. [Variables](#9-variables)
10. [Groups, facets and labels](#10-groups-facets-and-labels)
11. [Platform matching (`match`)](#11-platform-matching-match)
12. [Dialects](#12-dialects)
13. [Index files (catalogues)](#13-index-files-catalogues)
14. [Validation rules and limits](#14-validation-rules-and-limits)
15. [Testing a pack before you publish it](#15-testing-a-pack-before-you-publish-it)
16. [Worked examples](#16-worked-examples)
17. [Common mistakes](#17-common-mistakes)

---

## 1. The three file types

| Schema value        | What it is                                                   | Who writes it             |
| ------------------- | ------------------------------------------------------------ | ------------------------- |
| `socx.querypack/v1` | A **pack**: metadata + a list of templates                   | You                       |
| `socx.packindex/v1` | An **index**: a catalogue listing packs and/or other indexes | You, for multi‑file repos |
| `socx.dialects/v1`  | The **dialect** definitions                                  | Bundled — read only       |

> **Dialects cannot be shipped by a pack.** The `dialects` field of an index is
> informational; SOCx always uses its own bundled `dialects.json`. A pack that
> names a dialect the extension does not know is rejected. A new query language
> has to be added to the extension itself.

A pack file can be consumed in three ways:

- imported from a local `.json` file in **Extension settings → Query packs**;
- fetched from an HTTP or HTTPS URL added as a **source** (GitHub / GitLab /
  gist links are rewritten to their raw form automatically);
- referenced from an **index** that is itself the source URL.

> **Plain HTTP is accepted for internal repositories**, because a corporate
> query repository is often served by an ordinary HTTP server on the LAN. It is
> the weaker option: the query text is readable and rewritable in transit, and
> an access token added to the source is sent unencrypted too. SOCx marks such
> a source **not encrypted** in the settings; prefer HTTPS whenever the server
> offers it. No other scheme is accepted — `file:`, `ftp:` and the rest are
> refused.

All files must be plain JSON. The `jsonc` snippets below use comments only for
explanation — real files must not contain them.

---

## 2. Quick start

### 2.1 Minimal IOC pack

An **IOC pack** (`"kind": "ioc"`) is parameterised on the indicators the analyst
selected. Every template must bind at least one indicator type and must render
them.

```json
{
  "schema": "socx.querypack/v1",
  "id": "acme-defender",
  "kind": "ioc",
  "name": "ACME — Defender XDR",
  "dialect": "kql",
  "version": "2026-08-20",
  "templates": [
    {
      "id": "network-contact",
      "name": "Outbound contact with an indicator",
      "requiresIocs": true,
      "byType": {
        "IP": {
          "table": "DeviceNetworkEvents",
          "field": "RemoteIP",
          "op": "in~"
        },
        "Domain": {
          "table": "DeviceNetworkEvents",
          "field": "RemoteUrl",
          "op": "has_any"
        }
      },
      "body": "DeviceNetworkEvents\n| where Timestamp > ago(7d)\n| where {{field}} {{op}} ({{iocs}})\n| project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName"
    }
  ]
}
```

Selecting `203.0.113.10` and `evil.test` renders one query per indicator type
(or a single merged one — see [§8](#8-merged-multi-type-queries)):

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in~ ("203.0.113.10")
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName
```

### 2.2 Minimal standard (hunting) pack

A **standard pack** (`"kind": "standard"`) holds queries that need no indicator.
Every template must set `"requiresIocs": false` explicitly.

```json
{
  "schema": "socx.querypack/v1",
  "id": "acme-hunting-kql",
  "kind": "standard",
  "name": "ACME — hunting playbooks (KQL)",
  "dialect": "kql",
  "templates": [
    {
      "id": "encoded-powershell",
      "name": "Encoded PowerShell command lines",
      "requiresIocs": false,
      "body": "DeviceProcessEvents\n| where Timestamp > ago(7d)\n| where FileName in~ (\"powershell.exe\", \"pwsh.exe\")\n| where ProcessCommandLine has_any (\"-enc\", \"-EncodedCommand\", \"FromBase64String\")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine",
      "mitre": ["T1059.001", "T1027"]
    }
  ]
}
```

> IOC packs and standard packs are configured as **separate sources**, and a
> source only imports packs whose `kind` matches its own. Keep the two kinds in
> different files.

---

## 3. Pack reference

Top level fields of a `socx.querypack/v1` file:

| Field         | Type    | Required | Notes                                                                                       |
| ------------- | ------- | -------- | ------------------------------------------------------------------------------------------- |
| `schema`      | string  | **yes**  | Exactly `"socx.querypack/v1"`.                                                              |
| `id`          | string  | **yes**  | `^[a-z0-9][a-z0-9-]{0,63}$`. Unique inside a catalogue.                                     |
| `kind`        | string  | **yes**  | `"ioc"` or `"standard"`.                                                                    |
| `name`        | string  | **yes**  | ≤ 120 chars. Shown in the palette.                                                          |
| `dialect`     | string  | **yes**  | A bundled dialect id ([§12](#12-dialects)). Default for every template.                     |
| `description` | string  | no       | ≤ 2 000 chars.                                                                              |
| `vendor`      | string  | no       | ≤ 120 chars. Searchable.                                                                    |
| `author`      | string  | no       | ≤ 120 chars.                                                                                |
| `homepage`    | string  | no       | ≤ 500 chars.                                                                                |
| `version`     | string  | no       | ≤ 40 chars. A date such as `2026-08-20` works well.                                         |
| `license`     | string  | no       | ≤ 40 chars, e.g. `MIT`.                                                                     |
| `verified`    | boolean | no       | Only meaningful when attested by an index ([§13.4](#134-verification)).                     |
| `match`       | object  | no       | Console auto‑detection ([§11](#11-platform-matching-match)).                                |
| `targets`     | array   | no       | `{ id, label, baseUrl?, tenant? }`. Parsed and kept as metadata; no surface reads it today. |
| `variables`   | array   | no       | Analyst‑editable values ([§9](#9-variables)).                                               |
| `groups`      | array   | no       | Palette sections ([§10.1](#101-groups)).                                                    |
| `facets`      | array   | no       | Custom filter dimensions ([§10.2](#102-facets-and-labels)). Max 12.                         |
| `labels`      | object  | no       | Facet values applied to **every** template of the pack.                                     |
| `templates`   | array   | **yes**  | At least one template.                                                                      |

Unknown top level fields are silently dropped — not an error, but they do
nothing.

---

## 4. Templates

| Field            | Type    | Required | Notes                                                                                     |
| ---------------- | ------- | -------- | ----------------------------------------------------------------------------------------- |
| `id`             | string  | **yes**  | `^[a-z0-9][a-z0-9-]{0,63}$`, unique inside the pack.                                      |
| `name`           | string  | **yes**  | ≤ 160 chars.                                                                              |
| `body`           | string  | **yes**  | ≤ 20 000 chars. The query text ([§6](#6-the-template-body-language)).                     |
| `requiresIocs`   | boolean | see note | Defaults to **`true`**. Must be `true` in an `ioc` pack, `false` in a `standard` pack.    |
| `byType`         | object  | if IOC   | Indicator bindings ([§5](#5-indicator-bindings-bytype)).                                  |
| `description`    | string  | no       | ≤ 2 000 chars. Searched by the palette.                                                   |
| `group`          | string  | no       | `parent` or `parent/child`, ≤ 130 chars.                                                  |
| `tags`           | array   | no       | ≤ 200 strings of ≤ 500 chars. Searched.                                                   |
| `labels`         | object  | no       | Facet values for this template only.                                                      |
| `dialect`        | string  | no       | Overrides the pack dialect for this template.                                             |
| `excludePrivate` | boolean | no       | Drops RFC1918 / loopback / link‑local / ULA addresses before rendering.                   |
| `maxItems`       | number  | no       | Chunk size override, must be > 0. Defaults to the dialect's `maxItems`, then 100.         |
| `open`           | string  | no       | ≤ 2 000 chars. A URL template rendered next to the query ([§6.4](#64-the-open-template)). |
| `reference`      | string  | no       | ≤ 500 chars. Documentation link; searched in deep search.                                 |
| `mitre`          | array   | no       | ATT&CK technique ids, e.g. `["T1059.001"]`. Searched.                                     |

> `requiresIocs` defaults to `true`, so **a standard template that forgets
> `"requiresIocs": false` is rejected**, and so is an IOC template that sets it
> to `false`.

---

## 5. Indicator bindings (`byType`)

An IP lives in a different column than a hash, so a template declares, per
indicator type, where to look. `byType` maps a **bindable indicator type** to a
binding object.

Bindable types:

`IP` · `Domain` · `URL` · `Email` · `ASN` · `MAC` · `CVE` · `Hash` · `SHA256` ·
`SHA1` · `MD5`

Any other key is a validation **error**.

| Binding field | Type   | Rendered by                        | Notes                                                                  |
| ------------- | ------ | ---------------------------------- | ---------------------------------------------------------------------- |
| `table`       | string | `{{table}}`                        | ≤ 200 chars. Also blocks merging ([§8](#8-merged-multi-type-queries)). |
| `field`       | string | `{{field}}`, `{{iocs\|or-values}}` | ≤ 200 chars. The column compared against the indicators.               |
| `op`          | string | `{{op}}`, `{{iocs\|or-values}}`    | ≤ 40 chars. Falls back to the dialect's `equals` operator.             |
| `suffix`      | string | `{{iocs\|or-values}}`              | ≤ 40 chars. Appended after each comparison, e.g. UDM `nocase`.         |
| `note`        | string | —                                  | ≤ 500 chars. Author note; searched in deep search.                     |

```json
"byType": {
  "IP":     { "table": "DeviceNetworkEvents", "field": "RemoteIP", "op": "in~" },
  "SHA256": { "table": "DeviceFileEvents",    "field": "SHA256",   "op": "in~" },
  "MD5":    { "table": "DeviceFileEvents",    "field": "MD5",      "op": "in~" }
}
```

### Hashes: bind `MD5`, `SHA1` and `SHA256`, not `Hash`

SOCx detects a hash and then narrows it by length before matching bindings:
32 → `MD5`, 40 → `SHA1`, 64 → `SHA256`. Only a hash of some other length stays
`Hash`. A template that binds `Hash` alone therefore covers **none** of the
common hashes. Bind the three explicitly; a `Hash` binding is a reasonable extra
catch‑all.

An indicator type nobody binds is reported to the analyst as _uncovered_, never
silently dropped.

---

## 6. The template body language

The body is query text plus `{{placeholder}}` substitutions. A placeholder is
`{{name}}`, `{{name|filter}}` or `{{name|filter:argument}}`, and filters chain:
`{{iocs|regex|urlencode}}`.

### 6.1 Placeholders

| Placeholder  | Renders                                                                                       |
| ------------ | --------------------------------------------------------------------------------------------- |
| `{{iocs}}`   | The whole list of indicators of the current type — quoted, escaped and joined by the dialect. |
| `{{ioc}}`    | The **first** indicator only, quoted and escaped.                                             |
| `{{field}}`  | `byType[type].field`.                                                                         |
| `{{table}}`  | `byType[type].table`.                                                                         |
| `{{op}}`     | `byType[type].op`, or the dialect's `equals` operator.                                        |
| `{{count}}`  | Number of indicators in this query, after chunking.                                           |
| `{{chunk}}`  | 1‑based index of the current chunk.                                                           |
| `{{chunks}}` | Total number of chunks.                                                                       |
| `{{now}}`    | Current timestamp, ISO 8601 (`2026-08-20T09:12:34.567Z`).                                     |
| `{{query}}`  | The rendered query text — **only inside `open`**; empty in `body`.                            |
| `{{var:id}}` | The value of the declared variable `id` ([§9](#9-variables)).                                 |

Any other name is a validation error. An IOC template that never uses `{{iocs}}`
or `{{ioc}}` is rejected — it would silently ignore the analyst's selection.

### 6.2 List filters (for `{{iocs}}`)

One list filter is honoured per placeholder; it changes how the list is built.

| Filter                | Output                                                            | Example — `a.test`, `b.test` in KQL                        |
| --------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------- |
| _(none)_              | Quoted + escaped, joined by the dialect separator.                | `"a.test", "b.test"`                                       |
| `raw`                 | **Unquoted, unescaped**, joined by the separator.                 | `a.test, b.test`                                           |
| `json`                | A JSON array.                                                     | `["a.test","b.test"]`                                      |
| `regex`               | Regex alternation in parentheses, values regex‑escaped.           | `(a\.test\|b\.test)`                                       |
| `newline`             | One indicator per line, unquoted.                                 | `a.test` ⏎ `b.test`                                        |
| `or-terms`            | Quoted values joined by the dialect's `or` operator.              | `"a.test" or "b.test"`                                     |
| `or-values`           | `field op value` per indicator, joined by `or`, from the binding. | `RemoteUrl has_any "a.test" or RemoteUrl has_any "b.test"` |
| `or-values:FieldName` | Same, with an explicit field instead of the binding's.            | `Url has_any "a.test" or Url has_any "b.test"`             |

`raw` and `newline` bypass escaping — use them only where the surrounding syntax
makes injection impossible (a comment line, a CSV block, a lookup list).

### 6.3 Encoding filters (for any placeholder)

Applied to the built value, in the order written.

| Filter            | Effect                                                                                                                                                            |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `urlencode`       | `encodeURIComponent`.                                                                                                                                             |
| `base64`          | Standard base64 of the UTF‑8 bytes.                                                                                                                               |
| `upper` / `lower` | Case conversion.                                                                                                                                                  |
| `gzip_base64url`  | **Pass‑through in the synchronous renderer.** Reserved for `open` URLs that need a compressed payload; the value is left untouched so the preview stays readable. |

Unknown filter names are a validation error.

### 6.4 The `open` template

`open` is an optional URL template stored next to the query. It is validated
exactly like `body` — same placeholders, same filters — and additionally may use
`{{query}}`, which holds the already rendered query text.

```json
"open": "https://portal.example.test/hunting?query={{query|urlencode}}"
```

The renderer fills `openUrl` on every rendered query. No SOCx surface opens it
automatically today — the palette and the query workspace copy or insert the
query text — so treat `open` as forward‑looking metadata rather than a feature
your analysts can click.

### 6.5 Chunking and length

When the selection is larger than `maxItems` (template override → dialect value
→ 100), the renderer splits it into several queries and fills `{{chunk}}` /
`{{chunks}}`. A query longer than the dialect's `maxLength` (default 8 000) is
flagged as _over length_ in the UI rather than truncated.

```json
"body": "// batch {{chunk}}/{{chunks}} — {{count}} indicators\nDeviceFileEvents | where SHA256 in~ ({{iocs}})"
```

---

## 7. What the renderer does for you

Write plain query text; do **not** hand‑quote or hand‑escape values.

- **Quoting** — every value is wrapped in the dialect's `quote` character.
- **Escaping** — by the dialect's `escape` strategy:

  | Strategy    | Behaviour                                             |
  | ----------- | ----------------------------------------------------- |
  | `backslash` | Backslashes doubled, the quote character escaped.     |
  | `sql-quote` | Single quotes doubled.                                |
  | `lucene`    | Lucene reserved characters escaped.                   |
  | `regex`     | Regex metacharacters escaped.                         |
  | `json`      | JSON string escaping, without the surrounding quotes. |
  | `none`      | Verbatim (NetWitness).                                |

- **Joining** — with the dialect `separator`, or as a regex alternation for
  `regex-alternation` dialects (values regex‑escaped and left unquoted).
- **Deduplication** — repeated indicators are collapsed per type.
- **Private address filtering** — when `excludePrivate` is set.

### You still write the brackets

The dialect's `listOpen` / `listClose` are **descriptive metadata**; the renderer
does not insert them. Write the brackets yourself:

```jsonc
"body": "... | where {{field}} {{op}} ({{iocs}})"   // ✅ correct
"body": "... | where {{field}} {{op}} {{iocs}}"     // ❌ produces: in~ "a", "b"
```

For LogScale the list opener is `values=[`, so the body reads
`{{field}} in (values=[{{iocs}}])` — check the dialect entry when in doubt.

---

## 8. Merged multi-type queries

By default a template renders once per indicator type. The query workspace can
instead produce **one query covering every type**, joining the per‑type
comparisons with the dialect's `or`. This only works when SOCx can identify the
single comparison to repeat, and the rules are deliberately strict.

### Templates that never ask which type they render

The simplest case needs no merging at all. When the body contains **no**
`{{field}}`, `{{table}}` or `{{op}}` placeholder, and every bound type carries
the **same binding** — typically an empty one, as in a search that matches raw
terms anywhere in the event — the rendered text does not depend on the type of a
value. Splitting such a selection would produce several queries differing only
in which indicators they left out, so the whole selection goes into **one
query**, chunked as one list:

```json
{
  "id": "generic-ioc-correlation",
  "name": "Generic IOC correlation",
  "requiresIocs": true,
  "byType": { "IP": {}, "Domain": {}, "URL": {}, "SHA256": {} },
  "body": "search index={{var:index}} ({{iocs|or-terms}})\n| stats count by index, src_ip"
}
```

```spl
search index=main ("203.0.113.10" OR "evil.test" OR "aaaa…")
| stats count by index, src_ip
```

Bindings must be equal, not merely empty: `{{iocs|or-values}}` reads `field`,
`op` and `suffix` from the binding, so two types pointing at different fields
are still rendered separately. Switching to **One per type** still splits the
selection, for the analyst who wants one query per indicator kind.

### Templates that compare one field to one list

A template with per-type fields is mergeable when its body contains

- **exactly one** `{{field}}` placeholder, and
- **exactly one** `{{iocs}}` or `{{ioc}}` placeholder, after it, and
- nothing but `{{op}}` between them, and
- no line break between them, and
- **no** `{{table}}` placeholder anywhere,

and when every bound type shares the same `table`.

```jsonc
// ✅ mergeable — one field, one list, one line
"body": "DeviceNetworkEvents | where Timestamp > ago({{var:range}}) | where {{field}} {{op}} ({{iocs}})"

// ❌ not mergeable — the table changes per type
"body": "{{table}} | where {{field}} {{op}} ({{iocs}})"

// ❌ not mergeable — two comparisons
"body": "search {{field}} {{op}} ({{iocs}}) OR ParentField {{op}} ({{iocs}})"
```

Merged output for IPs and domains:

```kql
DeviceNetworkEvents | where Timestamp > ago(7d) | where RemoteIP in~ ("203.0.113.10") or RemoteUrl has_any ("evil.test")
```

When a merge is asked for and refused, SOCx falls back to one query per type and
says why — _"this template does not compare one field to one list…"_ or _"the
indicator types are read from different tables"_. Brackets opened inside the
comparison are carried along, so `in~ ({{iocs}})` stays correct. Chunking spans
the whole selection in merged mode, so one query stays one query for as long as
the platform allows it.

---

## 9. Variables

Variables are pack‑level, analyst‑editable values — a time range, an index name,
a tenant. Declared once, referenced as `{{var:id}}`.

Declaring them once for the whole pack does not mean every query is asked about
every one of them: the palette and the query workspace offer **only the
variables the selected template actually substitutes**, in `body` or in `open`.
A variable another template in the same file uses is simply not shown.

```json
"variables": [
  { "id": "range", "label": "Time range", "default": "7d", "options": ["1d", "7d", "30d"] },
  { "id": "index", "label": "Index", "default": "main", "description": "Splunk index to search" },
  { "id": "summariesonly", "label": "Summaries only", "type": "checkbox", "default": "true" }
]
```

| Field         | Required | Notes                                                      |
| ------------- | -------- | ---------------------------------------------------------- |
| `id`          | **yes**  | `^[a-z0-9][a-z0-9-]{0,63}$`, unique in the pack.           |
| `label`       | **yes**  | ≤ 120 chars.                                               |
| `type`        | no       | `"text"` (default) or `"checkbox"`.                        |
| `default`     | no       | ≤ 500 chars. Checkbox defaults are `"true"` or `"false"`.  |
| `options`     | no       | ≤ 200 values; offered as a choice list for non-checkboxes. |
| `description` | no       | ≤ 500 chars.                                               |

Rules:

- Referencing an undeclared variable is an **error**.
- A variable with no `default` renders as an empty string until it is filled in.
- A checkbox renders the literal string `true` or `false` into the query and
  cannot also declare `options`.
- Variable values are inserted verbatim — they are **not** quoted or escaped, so
  keep them to structural fragments (`7d`, `main`, `index=web`), never
  attacker‑controlled data.

```json
"body": "index={{var:index}} earliest=-{{var:range}} {{field}} IN ({{iocs}})"
```

---

## 10. Groups, facets and labels

### 10.1 Groups

Groups drive the palette sections and the context‑menu submenus. One optional
level of nesting is supported.

```json
"groups": [
  {
    "id": "network",
    "label": "Network",
    "description": "Egress, DNS, proxy",
    "order": 10,
    "children": [{ "id": "egress", "label": "Egress" }]
  }
],
"templates": [{ "id": "network-contact", "group": "network/egress", "name": "…", "body": "…" }]
```

- `id` follows the usual slug pattern; `group` is `parent` or `parent/child`.
- `order` sorts sections (lower first); groups without one sort by label.
- A `group` path the pack never declares is a **warning**, not an error: the
  section is synthesised from the path so a typo never hides a query.
- Templates with no `group` land in _Uncategorised_.

### 10.2 Facets and labels

A repository can declare its own filter dimensions — a customer, a tenant, a
squad, a maturity level. Each declared facet becomes a filter control in the
palette and in the query workspace.

```json
"facets": [
  { "id": "customer", "label": "Customer", "order": 1 },
  { "id": "maturity", "label": "Maturity", "description": "Detection confidence" }
],
"labels": { "customer": ["ACME"] },
"templates": [{ "id": "t1", "labels": { "maturity": ["production"] }, "name": "…", "body": "…" }]
```

- Max **12** facets per pack; facet ids follow the slug pattern.
- Label values are free text: ≤ 80 chars, up to 40 values per facet. A single
  string is accepted and normalised to a one‑element array.
- Pack labels apply to every template; template labels are merged on top.
- An index can declare facets for a whole catalogue and attach labels to whole
  pack files ([§13](#13-index-files-catalogues)).

---

## 11. Platform matching (`match`)

`match` tells SOCx which packs belong to the console open in the current tab.

```json
"match": {
  "hostnames": ["security.microsoft.com", "portal.azure.com"],
  "urlPatterns": ["^https://security\\.microsoft\\.com/v2/advanced-hunting"],
  "pathHint": "sentinel|logs|hunting",
  "note": "Sentinel lives inside the Azure portal, hence the path hint"
}
```

- `hostnames` match the host exactly or as a suffix (`sub.example.test` matches
  `example.test`). Worth 2 points.
- `urlPatterns` are JavaScript regular expressions tested against the full URL.
  Worth 2 points. A pattern longer than 500 characters, or containing a nested
  quantifier (catastrophic backtracking risk), is refused.
- `pathHint` is an extra regex, always case‑insensitive, tested against
  `pathname + search + hash` — the hash matters because single page consoles put
  the whole route after `#`. It applies only when host or URL already matched,
  and a pack whose hint fails is dropped.
- A leading `(?i)` in `pathHint` is stripped rather than allowed to break the
  pattern: JavaScript has no inline flags.

Escape backslashes for JSON: `\\.` written in the file is `\.` in the regex.

---

## 12. Dialects

`escape`, `quote`, `separator`, `maxItems` and `maxLength` are applied by the
renderer. `operators.equals` and `operators.or` are used by `{{op}}`,
`or-values`, `or-terms` and merging. Everything else (`listOpen`, `listClose`,
`timeExpression`, `comment`, `caseInsensitive`, `notes`) is documentation for
the template author.

| id           | Language                            | Escape      | Quote    | List strategy     | equals / in / or      | maxItems | maxLength |
| ------------ | ----------------------------------- | ----------- | -------- | ----------------- | --------------------- | -------- | --------- |
| `kql`        | Kusto — Defender XDR, Sentinel, ADX | `backslash` | `"`      | in-operator       | `==` / `in~` / `or`   | 100      | 8000      |
| `spl`        | Splunk SPL, Falcon Event Search     | `backslash` | `"`      | in-operator       | `=` / `IN` / `OR`     | 200      | 10000     |
| `udm`        | UDM Search — Google SecOps          | `backslash` | `"`      | or-expansion      | `=` / `=` / `OR`      | 150      | 6000      |
| `yaral`      | YARA-L 2.0                          | `backslash` | `"`      | or-expansion      | `=` / `in` / `or`     | 100      | 12000     |
| `logscale`   | CrowdStrike LogScale                | `backslash` | `"`      | in-operator       | `=` / `in` / `or`     | 200      | 8000      |
| `xql`        | Cortex XDR / XSIAM                  | `backslash` | `"`      | in-operator       | `=` / `in` / `or`     | 100      | 8000      |
| `aql`        | IBM QRadar Ariel                    | `sql-quote` | `'`      | in-operator       | `=` / `IN` / `OR`     | 200      | 12000     |
| `lucene`     | Lucene                              | `lucene`    | `"`      | or-expansion      | `:` / `:` / `OR`      | 300      | 6000      |
| `es-kql`     | Kibana Query Language               | `lucene`    | `"`      | or-expansion      | `:` / `:` / `or`      | 300      | 6000      |
| `esql`       | ES\|QL — Elastic                    | `backslash` | `"`      | in-operator       | `==` / `IN` / `OR`    | 200      | 8000      |
| `fortisiem`  | FortiSIEM filter                    | `backslash` | `"`      | in-operator       | `=` / `IN` / `OR`     | 100      | 5000      |
| `trend-v1`   | Trend Vision One Search             | `lucene`    | `"`      | or-expansion      | `:` / `:` / `OR`      | 100      | 5000      |
| `s1ql`       | SentinelOne Deep Visibility         | `backslash` | `"`      | in-operator       | `=` / `In` / `OR`     | 100      | 5000      |
| `leql`       | Rapid7 InsightIDR LEQL              | `backslash` | `"`      | in-operator       | `=` / `IN` / `OR`     | 100      | 5000      |
| `sumo`       | Sumo Logic                          | `backslash` | `"`      | in-operator       | `=` / `in` / `OR`     | 150      | 6000      |
| `devo`       | Devo LINQ                           | `backslash` | `"`      | in-operator       | `=` / `in` / `or`     | 150      | 6000      |
| `spotter`    | Securonix Spotter                   | `backslash` | `"`      | in-operator       | `=` / `IN` / `OR`     | 100      | 5000      |
| `ccl`        | ArcSight CCL                        | `backslash` | `"`      | or-expansion      | `=` / `=` / `OR`      | 100      | 5000      |
| `nwql`       | NetWitness                          | `none`      | _(none)_ | in-operator       | `=` / `=` / `\|\|`    | 100      | 4000      |
| `sql`        | SQL / osquery                       | `sql-quote` | `'`      | in-operator       | `=` / `IN` / `OR`     | 500      | 20000     |
| `regex`      | Regular expression — grep, ripgrep  | `regex`     | _(none)_ | regex-alternation | — / — / `\|`          | 1000     | 60000     |
| `powershell` | PowerShell                          | `regex`     | `'`      | regex-alternation | `-eq` / `-in` / `-or` | 500      | 20000     |

List strategies:

- **in-operator** — values quoted and joined by the separator, meant to sit
  inside brackets you write yourself.
- **or-expansion** — same joining, but the language has no `IN`; use
  `{{iocs|or-values}}` to expand into `field op value or …`.
- **regex-alternation** — values regex‑escaped, unquoted, joined by `|`.

Each source can be restricted to the dialects your SOC actually runs, and the
index names the language of every file, so unselected technologies are never
downloaded.

---

## 13. Index files (catalogues)

An index lets one URL serve a whole catalogue.

```json
{
  "schema": "socx.packindex/v1",
  "name": "ACME query catalogue",
  "description": "Detection content for the ACME SOC",
  "homepage": "https://github.com/acme/socx-query-packs",
  "version": "2026-08-20",
  "facets": [{ "id": "customer", "label": "Customer" }],
  "includes": ["customers/acme/index.json", "customers/globex/index.json"],
  "packs": [
    {
      "id": "acme-defender",
      "kind": "ioc",
      "name": "ACME — Defender XDR",
      "dialect": "kql",
      "path": "packs/acme-defender.json",
      "templates": 12,
      "verified": true,
      "labels": { "customer": ["ACME"] }
    }
  ]
}
```

### 13.1 Entry fields

| Field       | Required | Notes                                                                                         |
| ----------- | -------- | --------------------------------------------------------------------------------------------- |
| `id`        | **yes**  | Slug; must equal the pack file's own `id`.                                                    |
| `kind`      | **yes**  | `"ioc"` or `"standard"`; must equal the pack's `kind`.                                        |
| `path`      | **yes**  | Relative path, resolved against the index URL.                                                |
| `name`      | no       | Defaults to the id.                                                                           |
| `dialect`   | no       | Defaults to `"unknown"`. Used to skip downloads for unselected languages — **always set it**. |
| `templates` | no       | Expected template count; a mismatch aborts the whole source.                                  |
| `verified`  | no       | Attestation ([§13.4](#134-verification)).                                                     |
| `labels`    | no       | Facet values applied to every template of that file.                                          |

An entry with a missing or malformed `id`/`path` is skipped with a warning; a
bad `kind`, a duplicate `id` or an unsafe `path` is a hard error.

### 13.2 `includes`

`includes` points at other index files — or, for convenience, directly at pack
files — so a catalogue can be split per customer, per platform or per squad.

- Relative paths stay on the origin of the referencing index.
- Absolute URLs are allowed but must be **HTTP or HTTPS**. An HTTPS catalogue
  may include a file from a plain HTTP server — that hop is unencrypted, so use
  it only for internal hosts.
- `..` anywhere in a path is rejected, and so is a protocol‑relative
  `//host/file.json`, which is not relative at all — it changes host while
  keeping the scheme.
- Cycles and diamonds are ignored rather than fatal.
- Limits: **50** includes per file, **4** levels of nesting, **60** files per
  source in total.

An index may carry `packs`, `includes`, or both — a root index that only links
to its parts is valid.

### 13.3 Security rules for paths

Pack paths must resolve to the **same origin** as the index that names them —
same scheme, same host, same port. The scheme travels with the origin, so an
HTTPS catalogue cannot be talked into reading its packs over plain HTTP, and an
HTTP one cannot silently reach out to an HTTPS host. This is enforced at fetch
time, not only by the validator, and a violation aborts the source instead of
quietly skipping a file.

### 13.4 Verification

The index is the authority for the `verified` flag:

- if the entry sets `verified`, the pack takes that value;
- a pack file may repeat the field, but a value that **contradicts** the index
  aborts the source;
- a pack file that omits it is fine.

### 13.5 What aborts a whole source

Any of these fails the refresh and keeps the previously accepted cache:

- an entry whose pack id, kind or template count does not match the file;
- two files of the same catalogue declaring the same pack id;
- an HTML response (a `blob` URL that was not rewritten);
- a pack that fails validation;
- more than 60 files, or deeper than 4 include levels;
- a path leaving the origin.

### 13.6 Change pinning

Every file of the tree is hashed together with the dialect selection. When the
hash changes, the source is reported as **changed** and the new content has to be
accepted before it is used. Narrowing or widening the dialect selection re‑pins
the source as well.

---

## 14. Validation rules and limits

### 14.1 Hard errors — the pack is rejected

- `schema` is not `socx.querypack/v1`.
- `id` missing or not matching `^[a-z0-9][a-z0-9-]{0,63}$`.
- `kind` not `ioc` / `standard`; `name` missing; `dialect` missing or unknown.
- `templates` missing or empty.
- A template without a valid `id`, without `name`, or without `body`.
- Duplicate template ids, duplicate variable ids.
- `kind: "ioc"` with `requiresIocs: false`, or `kind: "standard"` without
  `requiresIocs: false`.
- `requiresIocs: true` with no `byType` binding.
- An IOC template whose `body`/`open` never uses `{{iocs}}` or `{{ioc}}`.
- An unknown placeholder, an unknown filter, an unknown indicator type in
  `byType`, an unknown template‑level dialect.
- `{{var:x}}` where `x` is not declared.

### 14.2 Warnings — accepted, but fix them

- A `group` path that does not match `parent[/child]`.
- A `group` path the pack does not declare (the section is synthesised).

The catalogue audit requires **zero warnings**.

### 14.3 Length and count limits

| Item                                         | Limit                   |
| -------------------------------------------- | ----------------------- |
| ids (pack, template, group, variable, facet) | 64 chars, slug pattern  |
| pack `name`                                  | 120 chars               |
| template `name`                              | 160 chars               |
| `description`                                | 2 000 chars             |
| `body`                                       | 20 000 chars            |
| `open`                                       | 2 000 chars             |
| `group` path                                 | 130 chars               |
| `tags`                                       | 200 entries × 500 chars |
| `facets`                                     | 12 per pack             |
| label values                                 | 40 per facet × 80 chars |
| `variables[].options`                        | 200 entries × 500 chars |
| index `includes`                             | 50 per file             |
| files per source                             | 60                      |
| include depth                                | 4                       |

Anything above a string limit is dropped as if absent — which usually surfaces
as "missing name" or "missing body" rather than as a length error.

---

## 15. Testing a pack before you publish it

### 15.1 In the extension

**Extension settings → Query packs → import a `.json` file.** Validation errors
are shown with their JSON path (`$.templates[3]: unknown placeholder "iocz"`).
Then open the **Query workspace**, paste a mixed indicator list, and read the
rendered output of every template.

### 15.2 Against the extension's own parser

The repository ships an optional audit test that runs a whole catalogue through
the real validator and renderer — the same code the extension runs — and fails
on unresolved placeholders, `undefined` in the output, empty queries, warnings,
or index/pack mismatches:

```bash
SOCX_QUERY_PACK_AUDIT_DIR=/path/to/your-query-packs pnpm vitest run src/utility/query/queryCatalog.audit.test.ts
```

On PowerShell:

```powershell
$env:SOCX_QUERY_PACK_AUDIT_DIR = "C:\path\to\your-query-packs"; pnpm vitest run src/utility/query/queryCatalog.audit.test.ts
```

The directory must contain an `index.json` whose entries point at your pack
files.

### 15.3 Pre-flight checklist

- [ ] `schema`, `id`, `kind`, `name`, `dialect` present and consistent with the index entry.
- [ ] One `kind` per file; IOC and standard packs live in separate files.
- [ ] Every template binds the indicator types it claims to cover — `MD5`, `SHA1`, `SHA256` rather than `Hash`.
- [ ] The list placeholder sits inside the brackets the language needs.
- [ ] No hand‑written quotes around `{{iocs}}` or `{{ioc}}`.
- [ ] Every `{{var:…}}` is declared, and every declared variable has a sane default.
- [ ] Every `group` used is declared; `order` set where the section order matters.
- [ ] `maxItems` reasonable for the platform.
- [ ] `mitre` and `reference` filled in — they are searchable and save the next analyst a lookup.
- [ ] The index entry's `templates` count matches the file.

---

## 16. Worked examples

### 16.1 Defender XDR (KQL) — a complete IOC pack

```json
{
  "schema": "socx.querypack/v1",
  "id": "acme-defender-xdr",
  "kind": "ioc",
  "name": "ACME — Microsoft Defender XDR",
  "description": "Indicator hunting across the Defender advanced hunting tables.",
  "vendor": "Microsoft",
  "author": "ACME SOC",
  "homepage": "https://github.com/acme/socx-query-packs",
  "license": "MIT",
  "version": "2026-08-20",
  "dialect": "kql",
  "match": {
    "hostnames": ["security.microsoft.com"],
    "pathHint": "advanced-hunting"
  },
  "variables": [
    {
      "id": "range",
      "label": "Time range",
      "default": "7d",
      "options": ["1d", "7d", "30d", "90d"]
    }
  ],
  "facets": [{ "id": "maturity", "label": "Maturity" }],
  "labels": { "customer": ["ACME"] },
  "groups": [
    {
      "id": "network",
      "label": "Network",
      "order": 10,
      "children": [{ "id": "egress", "label": "Egress" }]
    },
    { "id": "files", "label": "Files", "order": 20 }
  ],
  "templates": [
    {
      "id": "network-contact",
      "name": "Outbound contact with an indicator",
      "description": "Any device that reached an indicator over the network.",
      "group": "network/egress",
      "tags": ["network", "c2"],
      "labels": { "maturity": ["production"] },
      "requiresIocs": true,
      "excludePrivate": true,
      "byType": {
        "IP": {
          "table": "DeviceNetworkEvents",
          "field": "RemoteIP",
          "op": "in~"
        },
        "Domain": {
          "table": "DeviceNetworkEvents",
          "field": "RemoteUrl",
          "op": "has_any"
        },
        "URL": {
          "table": "DeviceNetworkEvents",
          "field": "RemoteUrl",
          "op": "has_any"
        }
      },
      "body": "DeviceNetworkEvents\n| where Timestamp > ago({{var:range}})\n| where {{field}} {{op}} ({{iocs}})\n| project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessAccountName\n| sort by Timestamp desc",
      "reference": "https://learn.microsoft.com/defender-xdr/advanced-hunting-devicenetworkevents-table",
      "mitre": ["T1071"]
    },
    {
      "id": "file-hash-sightings",
      "name": "File hash seen on a device",
      "group": "files",
      "requiresIocs": true,
      "maxItems": 50,
      "byType": {
        "SHA256": {
          "table": "DeviceFileEvents",
          "field": "SHA256",
          "op": "in~"
        },
        "SHA1": { "table": "DeviceFileEvents", "field": "SHA1", "op": "in~" },
        "MD5": { "table": "DeviceFileEvents", "field": "MD5", "op": "in~" }
      },
      "body": "// batch {{chunk}} of {{chunks}} — {{count}} hashes\nDeviceFileEvents\n| where Timestamp > ago({{var:range}})\n| where {{field}} {{op}} ({{iocs}})\n| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessAccountName",
      "mitre": ["T1204"]
    }
  ]
}
```

### 16.2 Splunk (SPL) with a variable index

```json
{
  "id": "network-contact",
  "name": "Network contact",
  "requiresIocs": true,
  "byType": {
    "IP": { "field": "dest_ip", "op": "IN" },
    "Domain": { "field": "query", "op": "IN" }
  },
  "body": "index={{var:index}} earliest=-{{var:range}}\n| search {{field}} {{op}} ({{iocs}})\n| stats count values(src_ip) as sources by {{field}}"
}
```

Renders as:

```spl
index=main earliest=-7d
| search dest_ip IN ("203.0.113.10", "198.51.100.7")
| stats count values(src_ip) as sources by dest_ip
```

### 16.3 Google SecOps UDM — a language without `IN`

`udm` uses `or-expansion`, and the binding's `suffix` carries the `nocase`
modifier:

```json
{
  "id": "udm-network",
  "name": "Network contact (UDM)",
  "requiresIocs": true,
  "byType": {
    "IP": { "field": "target.ip", "op": "=" },
    "Domain": { "field": "target.hostname", "op": "=", "suffix": "nocase" }
  },
  "body": "metadata.event_type = \"NETWORK_CONNECTION\" AND ({{iocs|or-values}})"
}
```

```text
metadata.event_type = "NETWORK_CONNECTION" AND (target.hostname = "evil.test" nocase OR target.hostname = "bad.test" nocase)
```

### 16.4 grep / ripgrep — a regex dialect

```json
{
  "schema": "socx.querypack/v1",
  "id": "acme-grep",
  "kind": "ioc",
  "name": "ACME — log grep",
  "dialect": "regex",
  "templates": [
    {
      "id": "grep-any",
      "name": "Search raw logs for any indicator",
      "requiresIocs": true,
      "byType": { "IP": {}, "Domain": {}, "URL": {}, "SHA256": {} },
      "body": "rg -n --no-heading -e '{{iocs|regex}}' /var/log"
    }
  ]
}
```

Two IPs render as one command:

```bash
rg -n --no-heading -e '(203\.0\.113\.10|198\.51\.100\.7)' /var/log
```

Note the empty binding objects: for a dialect with no fields, `byType` is what
declares _which indicator types this template accepts_, and that is enough.

Because the body has no `{{field}}` placeholder there is nothing to merge, so a
mixed selection still produces **one command per indicator type** — an IP
command and a domain command. That is usually what you want for grep; if you
prefer a single expression, write one template per type, or bind a single type
and let the analyst paste the whole list.

### 16.5 A standard pack with several dialects in one file

The pack declares a default dialect; individual templates override it.

```json
{
  "schema": "socx.querypack/v1",
  "id": "acme-hunting",
  "kind": "standard",
  "name": "ACME — hunting playbooks",
  "dialect": "kql",
  "groups": [{ "id": "execution", "label": "Execution" }],
  "templates": [
    {
      "id": "encoded-powershell-kql",
      "name": "Encoded PowerShell (Defender)",
      "group": "execution",
      "requiresIocs": false,
      "body": "DeviceProcessEvents\n| where ProcessCommandLine has_any (\"-enc\", \"FromBase64String\")",
      "mitre": ["T1059.001"]
    },
    {
      "id": "encoded-powershell-spl",
      "name": "Encoded PowerShell (Splunk)",
      "group": "execution",
      "dialect": "spl",
      "requiresIocs": false,
      "body": "index=windows EventCode=4688 (process=\"*-enc*\" OR process=\"*FromBase64String*\")\n| stats count by host, user, process",
      "mitre": ["T1059.001"]
    }
  ]
}
```

### 16.6 An MSSP catalogue split per customer

```text
index.json
├── customers/acme/index.json    → customers/acme/packs/acme-defender.json
└── customers/globex/index.json  → customers/globex/packs/globex-splunk.json
```

Root `index.json`:

```json
{
  "schema": "socx.packindex/v1",
  "name": "MSSP catalogue",
  "facets": [
    { "id": "customer", "label": "Customer", "order": 1 },
    { "id": "maturity", "label": "Maturity", "order": 2 }
  ],
  "includes": ["customers/acme/index.json", "customers/globex/index.json"],
  "packs": []
}
```

`customers/acme/index.json`:

```json
{
  "schema": "socx.packindex/v1",
  "name": "ACME",
  "packs": [
    {
      "id": "acme-defender",
      "kind": "ioc",
      "name": "ACME — Defender XDR",
      "dialect": "kql",
      "path": "packs/acme-defender.json",
      "templates": 12,
      "labels": { "customer": ["ACME"] }
    }
  ]
}
```

Paths are relative to the index that names them, and `..` is rejected — so keep
each customer's pack files under that customer's own directory, as above.

Facets declared at the root apply to every included file, and the labels on the
entry apply to every template of that file: the analyst gets a **Customer**
filter without a single line changing inside the pack.

---

## 17. Common mistakes

| Symptom                                                  | Cause and fix                                                                                                                                 |
| -------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `The URL returned a web page rather than a pack file`    | A GitHub/GitLab `blob` link that could not be rewritten. Use the raw URL.                                                                     |
| `unknown dialect "…"`                                    | Dialects are bundled; a pack cannot define one. Pick an id from [§12](#12-dialects).                                                          |
| `template needs indicators but binds no type`            | Add `byType`, or set `requiresIocs: false` and move it to a standard pack.                                                                    |
| `standard pack templates must set requiresIocs to false` | `requiresIocs` defaults to `true`. Set it explicitly in every standard template.                                                              |
| `template never renders its indicators`                  | The body has no `{{iocs}}` / `{{ioc}}`.                                                                                                       |
| `unknown placeholder "…"` / `unknown filter "…"`         | A typo, or a filter that does not exist. See [§6](#6-the-template-body-language).                                                             |
| `variable "…" is not declared`                           | Add it to the pack‑level `variables`.                                                                                                         |
| Output reads `in~ "a", "b"` without brackets             | Write the brackets in the body: `({{iocs}})`.                                                                                                 |
| Output is double quoted (`""a""`)                        | Quotes were written by hand around `{{iocs}}`. The renderer quotes for you.                                                                   |
| Hashes never match anything                              | Only `Hash` was bound. Bind `MD5`, `SHA1` and `SHA256`.                                                                                       |
| `index metadata does not match the pack`                 | The entry's `id`, `kind` or `templates` count differs from the file.                                                                          |
| `verification status does not match the index`           | Remove `verified` from the pack file, or align it with the index.                                                                             |
| `unsafe pack path "…"`                                   | `..`, a `//host/…` reference, or an absolute URL in `path`. Keep pack paths relative and on the origin.                                       |
| `pack paths must stay on the source origin`              | The index and its packs disagree on scheme, host or port — an HTTPS index cannot pull HTTP packs, or the reverse.                             |
| `Failed to fetch — this source is plain HTTP`            | The HTTP server is unreachable, or the browser/policy refused a non-TLS request. Check the host, then try HTTPS.                              |
| The source is reported as **changed**                    | Expected after any edit: the whole tree is content hashed and must be re‑accepted.                                                            |
| A query is flagged **over length**                       | Lower `maxItems` on the template, or narrow its projection.                                                                                   |
| A merge is refused                                       | The body does not compare one field to one list on one line, or the types read from different tables. See [§8](#8-merged-multi-type-queries). |

---

## See also

- [`README.md` → Query packs](../README.md#-query-packs) — the user‑facing overview
- [`docs/RELEASE_NOTES_1.1.0.md`](RELEASE_NOTES_1.1.0.md) — the release that introduced query packs
- [socx-query-packs](https://github.com/AlessioMobilia/socx-query-packs) — the community catalogue
