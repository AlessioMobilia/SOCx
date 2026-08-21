// The keyboard commands SOCx declares, in one place: the manifest names them,
// the background acts on them, and the options page lists them.
//
// The palette and smart formatter ship with suggested combinations. Everything
// else stays unbound until the analyst assigns a key in the browser's own
// shortcuts page.

import {
  callExtensionCallback,
  type ExtensionRuntimeError
} from "./extensionCallbacks"

export const QUERY_COMMAND = "open-query-palette"
export const SMART_FORMAT_COMMAND = "smart-format-selection"

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
    id: SMART_FORMAT_COMMAND,
    label: "Smart format selection",
    helper: "Formats the current selection and copies it to the clipboard."
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

type ShortcutManagerBridge = {
  openFirefoxSettings?: (callback: () => void) => void
  openTab: (url: string, callback: () => void) => void
  readLastError: () => ExtensionRuntimeError | undefined
}

/** Opens the browser-owned shortcut editor through the API supported there. */
export const openShortcutManager = (
  bridge: ShortcutManagerBridge,
  isFirefox: boolean,
  userAgent: string
): Promise<void> => {
  if (isFirefox) {
    const openFirefoxSettings = bridge.openFirefoxSettings
    if (!openFirefoxSettings) {
      return Promise.reject(
        new Error(
          "Open about:addons and choose Manage Extension Shortcuts from the settings menu."
        )
      )
    }
    return callExtensionCallback<void>(
      (callback) => openFirefoxSettings(callback),
      bridge.readLastError
    )
  }

  return callExtensionCallback<void>(
    (callback) =>
      bridge.openTab(shortcutSettingsUrl(false, userAgent), callback),
    bridge.readLastError
  )
}
