import { describe, expect, it, vi } from "vitest"

import {
  getContextMenuDefinitions,
  setupContextMenus,
  type ContextMenuApi
} from "./menus"

describe("context menu registration", () => {
  it("builds unique selection menu definitions with valid parents", () => {
    const definitions = getContextMenuDefinitions()
    const ids = definitions.map(({ id }) => String(id))
    const idSet = new Set(ids)

    expect(definitions.length).toBeGreaterThan(10)
    expect(idSet.size).toBe(ids.length)
    expect(
      definitions.every(({ contexts }) => contexts?.includes("selection"))
    ).toBe(true)

    definitions.forEach(({ parentId }) => {
      if (parentId) expect(idSet.has(String(parentId))).toBe(true)
    })
  })

  it("removes stale entries before recreating every menu in order", async () => {
    const calls: string[] = []
    const api: ContextMenuApi = {
      removeAll: vi.fn(async () => {
        calls.push("removeAll")
      }),
      create: vi.fn(async ({ id }) => {
        calls.push(`create:${String(id)}`)
      }),
      onClicked: { addListener: vi.fn() }
    }

    await setupContextMenus(api)

    const definitions = getContextMenuDefinitions()
    expect(calls[0]).toBe("removeAll")
    expect(calls.slice(1)).toEqual(
      definitions.map(({ id }) => `create:${String(id)}`)
    )
  })

  it("stops registration when a menu cannot be created", async () => {
    const api: ContextMenuApi = {
      removeAll: vi.fn(async () => undefined),
      create: vi.fn(async () => {
        throw new Error("permission denied")
      }),
      onClicked: { addListener: vi.fn() }
    }

    await expect(setupContextMenus(api)).rejects.toThrow("permission denied")
    expect(api.create).toHaveBeenCalledTimes(1)
  })
})
