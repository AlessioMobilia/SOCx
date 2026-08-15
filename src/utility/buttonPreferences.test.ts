import { describe, expect, it } from "vitest"

import {
  resolveSelectionButtonsPreference,
  resolveServicePageCopyButtonsPreference
} from "./buttonPreferences"

describe("button preferences", () => {
  it("enables both button families by default", () => {
    expect(resolveSelectionButtonsPreference(undefined)).toBe(true)
    expect(resolveServicePageCopyButtonsPreference(undefined)).toBe(true)
  })

  it("inherits the legacy selection value until the new preference is saved", () => {
    expect(resolveServicePageCopyButtonsPreference(undefined, false)).toBe(
      false
    )
    expect(resolveServicePageCopyButtonsPreference(undefined, true)).toBe(true)
  })

  it("keeps an explicit service-page preference independent", () => {
    expect(resolveServicePageCopyButtonsPreference(true, false)).toBe(true)
    expect(resolveServicePageCopyButtonsPreference(false, true)).toBe(false)
  })
})
