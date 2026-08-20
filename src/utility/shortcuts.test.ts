import { existsSync, readFileSync } from "node:fs"
import { describe, expect, it } from "vitest"

import {
  commandPage,
  QUERY_COMMAND,
  SHORTCUT_COMMANDS,
  shortcutSettingsUrl
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

  it("ships only the palette bound, so nothing is taken by surprise", () => {
    const declared = manifestCommands()
    const withDefaults = Object.entries(declared)
      .filter(([, command]) => command.suggested_key)
      .map(([id]) => id)
    expect(withDefaults).toEqual([QUERY_COMMAND])
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

  it("has no page for the palette, which opens in the current tab", () => {
    expect(commandPage(QUERY_COMMAND)).toBeUndefined()
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
})
