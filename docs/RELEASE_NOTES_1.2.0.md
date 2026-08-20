# SOCx 1.2.0

SOCx 1.2.0 turns the query palette from a list you scroll into a library you
navigate: starred queries, filters that stay where you left them, search that
reaches inside the query text, and catalogues that a SOC can organise across as
many files and dimensions as it needs.

## Favorite queries

Any template can be starred, from the palette or from the Query workspace, with
`Alt+F` or the ☆ next to its name. Favorites are pinned to the top of the list
under **★ Favorites**, on every console, and a filter shows only them. What is
stored is the namespaced template key, not a copy of the query, so a favorite
keeps pointing at the current version of the template after a pack refresh.

## A palette you can filter

The palette no longer opens as one long list. Two rows sit under the search
field: a segmented control that chooses the library — **All queries**, **IOC**,
**Hunting** — and a row of narrowing filters for language, category, favorites
and any dimension the repository declared.

Every control stays on screen whatever is selected, and every value keeps its
place: a value that no longer matches anything is shown counting zero instead of
disappearing, and the order never changes while you type. Counts are cross
filtered, so switching from KQL to SPL always shows a live number rather than a
dead end. Long result sets are drawn 40 rows at a time.

Rows now carry the template description under the name, and the preview shows
kind, language, verification state and tags as badges.

## The indicator list, in the palette

The preview column now opens with an editable **indicator field**. It is
prefilled from the selection, or from the Bulk Check workspace, reports what it
recognised — `3 indicators · 2 IP · 1 Domain` — and re-renders the query as it
is edited, so a missing address no longer means closing the palette, selecting
again and reopening. Inside the field, Enter adds a line and the arrows move the
caret instead of driving the result list.

## One query for the whole selection

A template binds each indicator type to its own column, and SOCx used to render
one query per type: an IP query, a domain query, a hash query. It now merges
them by default into a **single query**, each type compared against its own
field and the comparisons joined by the dialect's `or`:

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in~ ("8.8.8.8", "1.1.1.1") or RemoteUrl has_any ("evil.example")
```

Everything outside the comparison is rendered once, chunking now spans the whole
selection rather than each type separately, and a **Single query / One per
type** switch next to the indicator list turns the behaviour off; the choice is
remembered. Merging is refused — with the reason shown, falling back to one
query per type — when the types are read from different tables or when the body
is not a single field-to-list comparison, so nothing is ever guessed at.

Hunting queries take no indicator: selecting one hides the indicator list
instead of inviting an input that would be ignored.

## Search inside the queries

Search covers the name, description, group, pack, tags and custom labels — and
the query itself: its statement, the tables, fields and operators it binds per
indicator type, its ATT&CK references. Looking for `DeviceNetworkEvents`,
`src_ip` or `T1059` finds the templates that actually contain them. Terms
separated by spaces must all match, and a literal hit in the name outranks one
in the query body.

## Catalogues split across files, and custom dimensions

A source URL may point at a single pack, at a catalogue index, or at an index
that only **links to other index files** through `includes`. Included files are
followed recursively — HTTPS only, no path traversal, capped in depth and file
count, cycles ignored, a duplicate pack id within one catalogue refused — and
every file of the tree is covered by the same SHA-256 pin, so a change anywhere
still has to be accepted before it is used. One link can now serve a catalogue
that is organised per platform, per team or per customer.

Beyond groups, a repository can declare **its own filter dimensions**: `facets`
on a pack or on an index (`customer`, `tenant`, `squad`), and `labels` on
templates — or on whole pack files, from the index entry, which tags a file
without touching its content. Every declared dimension becomes a filter in the
palette and in the Query workspace.

## Keyboard shortcuts

Settings gained a **Keyboard shortcuts** section listing every SOCx window that
can be opened from the keyboard — query palette, Bulk IOC check, Query
workspace, Rule builder, Subnet extractor, Subnet abuse check — with the
combination currently bound to each, and a route to the browser page where they
are assigned. Only the palette ships with a default (`Ctrl+Shift+K`): the new
commands start **disabled**, so SOCx never takes a combination away from the
console being used until the analyst chooses one.

## Settings

Query pack settings now separate the two libraries into **IOC queries** and
**Hunting queries** tabs, each with its own sources and its own add form.

Every source can be restricted to the **technologies actually in use**: select
`KQL` and `SPL` and the packs written in the other languages are never
downloaded, because the catalogue index names the language of each file before
it is fetched. Changing the selection re-imports and re-pins that source.

The popup lists **Query workspace** right under Field notes.

## Fixes

The Query workspace listed every matching template in one column whose height
had a floor but no ceiling, so a few hundred templates stretched the row and the
whole page scrolled instead of the list. The three columns are now bound to the
viewport and scroll inside their own card, and the template list is **paged**:
25 at a time, with the range on top (`26–50 of 80 templates`) and a pager at the
bottom that returns to the first row of each page.

The Query workspace tab read its library once, when it was opened, so a source
enabled elsewhere, a technology selection changed in the settings or a personal
template saved in the builder left it showing a stale catalogue. It now follows
the same storage changes the context menus already followed, and reloads on its
own.

## Validation

278 unit tests, including the palette overlay itself (filters, starring, deep
search) driven through a DOM; type check; Chrome, Edge and Firefox builds with
manifest and bundle validation.
