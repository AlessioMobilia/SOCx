import { describe, expect, it } from "vitest"

import { shortcutSettingsUrl } from "./shortcut"

describe("query shortcut settings", () => {
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
