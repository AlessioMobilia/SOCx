# SOCx 1.3.0

SOCx 1.3.0 opens the query catalogue to the repositories a SOC actually runs
internally — including the ones served over plain HTTP — and documents the pack
format in full, in this repository, for anyone writing their own queries.

## Query repositories over plain HTTP

A query source had to be HTTPS. That is right for a public catalogue and wrong
for the internal ones: a wiki server, a file server or a GitLab instance on the
corporate network is very often plain `http://`, and those repositories were
simply unusable.

Sources may now be added over **HTTP as well as HTTPS**, as single pack files,
as catalogue indexes, and as includes inside an index. Nothing else changed
about how a pack is read: it is still validated field by field, still holds no
executable content, still pinned by SHA-256 content hash, and a change still has
to be accepted before it is used.

No other scheme is accepted — `file:`, `ftp:` and the rest are refused before
any request is made.

### Said plainly, wherever the source is shown

Clear text is the weaker option and SOCx says so rather than hiding it:

- a source fetched over HTTP carries a **not encrypted** badge in the Query
  packs settings, with a tooltip explaining that anyone on the network path can
  read the queries and replace them with their own;
- typing an `http://` URL into the add form warns before the source is added,
  and says explicitly that an **access token would be sent unencrypted too**;
- a plain HTTP source that cannot be reached now reports that it is plain HTTP
  and that the browser or a policy may have refused the request, instead of a
  bare `Failed to fetch`.

### Permissions

Fetching those repositories needs the browser's permission for HTTP origins, so
the extension now declares `http://*/*` next to the `https://*/*` it already
held. It is used for query pack sources; indicator lookups keep going to the
services configured in the settings.

## Catalogue paths are stricter

Two hardening changes came with the scheme work:

- a pack path must stay on the **exact origin** of the index that named it,
  scheme included. An HTTPS catalogue can no longer be talked into reading its
  packs over plain HTTP, and an HTTP one cannot reach out to an HTTPS host;
- a **protocol-relative** reference such as `//elsewhere.example/pack.json` —
  which looks relative but changes host while keeping the scheme — is now
  refused by the validator, with the same "unsafe path" error as `..`, instead
  of being caught later by the origin check.

## The pack format, documented in the repository

[`docs/QUERY_PACK_FORMAT.md`](QUERY_PACK_FORMAT.md) is a complete, code-derived
reference for writing the JSON files: every field of a pack and of an index with
its type and limits, the placeholder and filter syntax of a template body, what
the renderer quotes and escapes for you and what you still write yourself, the
rules that decide whether a template can be merged into a single query, the
table of the 22 bundled dialects, the validation errors and warnings, and worked
examples for Defender, Splunk, Google SecOps, grep and an MSSP catalogue split
per customer.

Every JSON example in it is checked against the extension's own validator and
renderer, so what the page shows is what SOCx produces.

## Validation

288 unit tests, including an end-to-end import of an HTTP catalogue and its
packs; type check; Chrome, Edge and Firefox builds with manifest and bundle
validation.
