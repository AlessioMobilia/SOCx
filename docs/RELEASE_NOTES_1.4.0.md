# SOCx 1.4.0

Smart formatting now reconstructs the fields visible on a security page instead
of depending primarily on its raw DOM text. This improves copied results from
SIEM, EDR, XDR and OSINT interfaces while keeping unrelated widget state out of
the clipboard.

## Visual field reconstruction

SOCx freezes the current rendered selection before hover effects, virtualized
rows or page mutations can alter it. It can then associate labels and values
that are placed on the same row, stacked vertically, repeated in CSS Grid or
Flex layouts, or arranged as a row of labels above a row of values. Open Shadow
DOM selections are supported for component-heavy sites.

The semantic fallback covers native tables, ARIA grids, definition lists,
accessible labelled groups and common field attributes. Two-column OSINT
summary tables with a spanning section title become aligned key/value text,
while genuine event tables with two populated column headers remain Markdown.
Multiline and repeated values are retained.

Tooltip roots, hidden descendants, copy/menu controls and internal serialized
attributes are excluded. A weak or ambiguous layout is left as rendered text
instead of being guessed from a broad ancestor.

## Partial JSON recovery

Copied JSON fragments can be formatted even when the outer object or closing
delimiters are missing. Recovery also handles HTML whitespace entities, padded
keys and values, escaped Markdown underscores, trailing commas and copied
`*,*` comma markers. Every recovered candidate must still pass `JSON.parse`;
broken strings, mismatched delimiters and property-like prose are rejected.

## Configurable shortcut

Press **Alt+Shift+F** by default to smart-format and copy the current selection.
The browser command can be changed from SOCx Options, alongside the other
keyboard shortcuts.

## Validation

333 tests cover visual, semantic and structured-text extraction, including
positive and negative fixtures modeled on recurring SIEM, EDR, XDR and OSINT
layouts. Type checking and the Chrome, Edge and Firefox builds pass, including
manifest and runtime-bundle validation.
