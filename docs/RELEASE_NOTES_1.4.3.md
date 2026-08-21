# SOCx 1.4.3

This patch adds first-class checkbox variables to query packs and accompanies a
safer, more useful release of the public SOCx query catalogue.

## Checkbox query variables

Query packs can declare boolean variables with `"type": "checkbox"`. SOCx
renders them as checkboxes in the query palette and workspace, and the query
builder can create and edit them directly. Their values are rendered as the
literal strings `true` and `false`, which makes Splunk `tstats` options such as
`summariesonly` and `allow_old_summaries` easy to control without free-form
input.

Validation rejects invalid checkbox defaults and checkbox variables with option
lists. Existing text and select variables remain fully compatible.

## Public query catalogue

The coordinated catalogue update focuses on useful, commonly run queries while
retaining more specific investigation paths. It also:

- corrects Splunk accelerated-data-model categorisation;
- adds checkbox controls for `tstats` summary options;
- fixes Microsoft Defender device-name filters in collection and exfiltration
  queries;
- uses `XmlWinEventLog` for Windows Security events;
- removes deprecated CrowdStrike queries based on the Splunk data model;
- searches generic endpoint hashes inline instead of relying on a `file_hash`
  field that may not exist;
- reduces expensive `_raw` regular expressions to the cases where they provide
  clear investigative value.

## Validation

Regression tests cover checkbox parsing, rendering and authoring. The complete
349-test suite, type checking, Chrome, Edge and Firefox packaging, manifest
checks, and Firefox linting pass before release. The public catalogue validator
also passes across 22 dialects, 14 packs and 139 templates without warnings.
