export const QUERY_COMMAND = "open-query-palette"

export const shortcutSettingsUrl = (
  isFirefox: boolean,
  userAgent: string
): string => {
  if (isFirefox) return "about:addons"
  return /Edg\//.test(userAgent)
    ? "edge://extensions/shortcuts"
    : "chrome://extensions/shortcuts"
}
