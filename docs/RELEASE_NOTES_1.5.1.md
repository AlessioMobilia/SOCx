# SOCx 1.5.1

This patch improves smart formatting for Splunk field and notable-event detail
tables.

## Splunk table formatting

Smart formatting now recognizes both classic Splunk field tables and Splunk
Enterprise Security detail tables. It extracts the field-name and value columns
while excluding grouping labels, visibility toggles, workflow menus and action
columns.

Multi-valued fields that use row spans, such as `eventtype`, retain every value
as a repeated key/value line.

## Two-column tables

Tables with exactly two populated columns are formatted as aligned key/value
lines, including tables with explicit column headers and selections clipped to
only their data cells. Tables with three or more data columns continue to use
Markdown table formatting.

## Validation

Regression coverage includes the classic Splunk search field table, Splunk
Enterprise Security notable fields, multi-valued rows and generic two-column
tables through both container and live-selection flows.
