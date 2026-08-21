import { existsSync, readFileSync } from "node:fs"
import { describe, expect, it, vi } from "vitest"

import {
  commandPage,
  DEFAULT_QUERY_SHORTCUT,
  DEFAULT_SMART_FORMAT_SHORTCUT,
  firefoxDefaultShortcutUpdates,
  openShortcutManager,
  QUERY_COMMAND,
  SHORTCUT_COMMANDS,
  shortcutSettingsUrl,
  SMART_FORMAT_COMMAND
} from "./shortcuts"

const manifestCommands = (): Record<
  string,
  { description?: string; suggested_key?: Record<string, string> }
> => JSON.parse(readFileSync("package.json", "utf8")).manifest.commands ?? {}

describe("shortcut catalogue", () => {
  it("declares every command it acts on in the manifest", () => {
    const declared = manifestCommands()
    for (const command of SHORTCUT_COMMANDS) {
      expect(declared[command.id]).toBeDefined()
      expect(declared[command.id].description).toBeTruthy()
    }
  })

  it("lists every declared command in the options page", () => {
    const known = new Set(SHORTCUT_COMMANDS.map((command) => command.id))
    for (const id of Object.keys(manifestCommands())) {
      expect(known.has(id)).toBe(true)
    }
  })

  it("ships defaults for the two in-page commands", () => {
    const declared = manifestCommands()
    const withDefaults = Object.entries(declared)
      .filter(([, command]) => command.suggested_key)
      .map(([id]) => id)
    expect(withDefaults).toEqual([QUERY_COMMAND, SMART_FORMAT_COMMAND])
    expect(declared[QUERY_COMMAND].suggested_key?.default).toBe(
      DEFAULT_QUERY_SHORTCUT
    )
    expect(declared[SMART_FORMAT_COMMAND].suggested_key?.default).toBe(
      DEFAULT_SMART_FORMAT_SHORTCUT
    )
  })

  it("points every command at a page that exists", () => {
    for (const command of SHORTCUT_COMMANDS) {
      if (!command.page) continue
      const source = command.page
        .replace(/^tabs\//, "src/tabs/")
        .replace(/\.html$/, ".tsx")
      expect(existsSync(source), source).toBe(true)
      expect(commandPage(command.id)).toBe(command.page)
    }
  })

  it("has no page for commands that act in the current tab", () => {
    expect(commandPage(QUERY_COMMAND)).toBeUndefined()
    expect(commandPage(SMART_FORMAT_COMMAND)).toBeUndefined()
  })

  it("routes each browser to its native shortcut manager", () => {
    expect(shortcutSettingsUrl(true, "Firefox/141")).toBe("about:addons")
    expect(shortcutSettingsUrl(false, "Edg/140.0")).toBe(
      "edge://extensions/shortcuts"
    )
    expect(shortcutSettingsUrl(false, "Chrome/140.0")).toBe(
      "chrome://extensions/shortcuts"
    )
  })

  it("uses Firefox's dedicated shortcut manager API", async () => {
    const openFirefoxSettings = vi.fn(async () => undefined)
    const openTab = vi.fn()

    await openShortcutManager(
      { openFirefoxSettings, openTab, readLastError: () => undefined },
      true,
      "Firefox/147"
    )

    expect(openFirefoxSettings).toHaveBeenCalledOnce()
    expect(openFirefoxSettings).toHaveBeenCalledWith()
    expect(openTab).not.toHaveBeenCalled()
  })

  it("migrates only Firefox shortcuts matching previously shipped defaults", () => {
    expect(
      firefoxDefaultShortcutUpdates([
        { name: QUERY_COMMAND, shortcut: "Ctrl+Shift+K" },
        { name: SMART_FORMAT_COMMAND, shortcut: "Alt + Shift + F" },
        { name: "open-bulk-check", shortcut: "Ctrl+Shift+B" }
      ])
    ).toEqual([
      { name: QUERY_COMMAND, shortcut: DEFAULT_QUERY_SHORTCUT },
      {
        name: SMART_FORMAT_COMMAND,
        shortcut: DEFAULT_SMART_FORMAT_SHORTCUT
      }
    ])
  })

  it("preserves custom and disabled Firefox shortcuts", () => {
    expect(
      firefoxDefaultShortcutUpdates([
        { name: QUERY_COMMAND, shortcut: "Ctrl+Shift+7" },
        { name: SMART_FORMAT_COMMAND, shortcut: "" },
        { name: "open-bulk-check" }
      ])
    ).toEqual([])
  })

  it("also migrates the interim Firefox query shortcut from 1.4.1", () => {
    expect(
      firefoxDefaultShortcutUpdates([
        { name: QUERY_COMMAND, shortcut: "Alt+Shift+Q" }
      ])
    ).toEqual([{ name: QUERY_COMMAND, shortcut: DEFAULT_QUERY_SHORTCUT }])
  })

  it("opens Chromium's shortcut page in a tab", async () => {
    const openTab = vi.fn((_url: string, callback: () => void) => callback())

    await openShortcutManager(
      { openTab, readLastError: () => undefined },
      false,
      "Edg/147"
    )

    expect(openTab).toHaveBeenCalledWith(
      "edge://extensions/shortcuts",
      expect.any(Function)
    )
  })

  it("gives actionable guidance on Firefox versions without the manager API", async () => {
    await expect(
      openShortcutManager(
        { openTab: vi.fn(), readLastError: () => undefined },
        true,
        "Firefox/136"
      )
    ).rejects.toThrow("Manage Extension Shortcuts")
  })
})
