# SOCx 1.5.0

This release turns Query workspace and the in-page query palette into a shared,
more capable investigation surface, and adds an integrated reference for every
query language supported by SOCx.

## Unified query browser

Query workspace and the in-page palette now use the same maintained browser,
filtering and rendering implementation while adapting their layout to the
available space. The full page follows the same shell, margins and visual
language as Bulk Check, uses a comfortable scrolling document and keeps the
template list and query preview stable while selections change. The compact
palette retains a constrained multi-column layout and can be closed directly.

The browser can filter templates by their repository source, distinguishing the
SOCx community catalogue, personal queries and repositories added in settings.
Search also reaches query bodies, fields and values. Scrollbars, boolean
controls, long option labels and filter help now match the rest of the SOCx UI,
without horizontal overflow or truncated preview labels.

The page context menu opens the query palette. When a console blocks palette
injection, SOCx falls back to Query workspace instead. Recognised SIEM and EDR
pages preselect their matching source and language in the palette; the
standalone workspace remains neutral.

## Query language mini guide

The collapsed mini guide covers all 22 bundled dialects, including regular
expressions and PowerShell. It can be filtered by language and product, or
searched by command, operator, field, option and example. Commands open to show
concise syntax, important options and short examples, while field sections
explain the main data fields and common usage patterns.

Splunk coverage includes default, internal and CIM fields as well as `stats`,
`eventstats`, `streamstats`, `tstats`, `chart`, `bin` and common statistical
functions. Every language links to its official documentation in a new tab.
Query workspace starts with **All languages and products**; only a palette on a
recognised console starts from that platform's language.

## Validation

Regression tests cover the shared browser, source and platform filtering,
language-guide defaults, command details, indicator scrolling and long option
labels. The complete 365-test suite, type checking, Chrome, Edge and Firefox
packaging, manifest validation and Firefox linting pass before release.
