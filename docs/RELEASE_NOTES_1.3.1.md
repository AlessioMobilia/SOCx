# SOCx 1.3.1

Three fixes to how a query is presented and rendered, all reported from a
Splunk pack whose templates share one set of pack-level variables.

## Only the variables a query actually uses

Variables are declared once per pack and shared by every template in it, and the
palette and the Query workspace offered all of them on every query. A template
that reads `{{var:index}}` and `{{var:time-span}}` also showed the fields other
templates in the same file use — a destination domain, a pre-filter — and
filling one in changed nothing, because the body never substitutes it.

Both surfaces now offer **only the variables the selected template substitutes**,
in its `body` or in its `open` URL. Nothing changed in the rendered query; what
changed is that the form no longer asks for values it will not use.

## The query stays on screen

In the palette, the name, badges, description and variable fields shared one
scrolling column with the query itself, so a template carrying several of them
pushed its own output below the fold.

The descriptive part now sits in a band that stops at 45% of the column and
scrolls on its own, while the query keeps the rest with a floor of 120 pixels:
the band above shrinks rather than the query disappearing. Variable fields are
laid out in a grid that follows the available width instead of one row each, and
tags past the fourth collapse into a `+N` badge listing the rest in its tooltip.
The Query workspace preview gained the same split.

## One query for a template that never asks which type it renders

A template that binds several indicator types to empty bindings and searches the
values as raw terms — `search index=main ({{iocs|or-terms}})` — was split into
one query per indicator type, because merging looked for a single
`{{field}} … {{iocs}}` comparison and found none.

When the body contains no `{{field}}`, `{{table}}` or `{{op}}` placeholder and
every bound type carries the same binding, the rendered text cannot depend on
the type of a value, so the whole selection now goes into **one query**, chunked
as a single list. Bindings must be equal rather than merely empty, because
`or-values` reads `field`, `op` and `suffix` from them; and **One per type**
still splits the selection for whoever wants it that way.

## Validation

295 unit tests, including the two reported templates rendered end to end and the
palette overlay driven through a DOM; type check; Chrome, Edge and Firefox
builds with manifest and bundle validation.
