// The keyboard commands SOCx declares, in one place: the manifest names them,
// the background acts on them, and the options page lists them.
//
// Only the palette ships with a suggested combination. Everything else is
// declared without one, so it stays unbound until the analyst assigns a key in
// the browser's own shortcuts page — a browser will not let an extension take
// a combination on its own, and an unused default would silently shadow a
// shortcut of the console the analyst is working in.

export const QUERY_COMMAND = "open-query-palette"

export type ShortcutCommand = {
  id: string
  label: string
  helper: string
  /** Extension page the command opens, if it opens one. */
  page?: string
}

export const SHORTCUT_COMMANDS: ShortcutCommand[] = [
  {
    id: QUERY_COMMAND,
    label: "Query palette",
    helper: "Opens the in-page palette on the console you are working in."
  },
  {
    id: "open-bulk-check",
    label: "Bulk IOC check",
    helper: "Opens the bulk check workspace.",
    page: "tabs/bulk-check.html"
  },
  {
    id: "open-query-workspace",
    label: "Query workspace",
    helper: "Opens the standalone query workspace.",
    page: "tabs/query-workspace.html"
  },
  {
    id: "open-query-builder",
    label: "Rule builder",
    helper: "Opens the builder for your own query templates.",
    page: "tabs/query-builder.html"
  },
  {
    id: "open-subnet-extractor",
    label: "Subnet extractor",
    helper: "Opens the CIDR extractor.",
    page: "tabs/subnet-extractor.html"
  },
  {
    id: "open-subnet-check",
    label: "Subnet abuse check",
    helper: "Opens the AbuseIPDB subnet drill-down.",
    page: "tabs/subnet-check.html"
  }
]

/** Page opened by a command, or `undefined` when it does something else. */
export const commandPage = (commandId: string): string | undefined =>
  SHORTCUT_COMMANDS.find((command) => command.id === commandId)?.page

export const shortcutSettingsUrl = (
  isFirefox: boolean,
  userAgent: string
): string => {
  if (isFirefox) return "about:addons"
  return /Edg\//.test(userAgent)
    ? "edge://extensions/shortcuts"
    : "chrome://extensions/shortcuts"
}
