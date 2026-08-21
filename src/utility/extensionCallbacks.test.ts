import { describe, expect, it, vi } from "vitest"

import { callExtensionCallback, resolveActiveTab } from "./extensionCallbacks"

describe("callback WebExtension API bridge", () => {
  it("resolves a Firefox-style callback result", async () => {
    const invoke = vi.fn((callback: (value: string[]) => void) => {
      callback(["active-tab"])
    })

    await expect(
      callExtensionCallback(invoke, () => undefined)
    ).resolves.toEqual(["active-tab"])
    expect(invoke).toHaveBeenCalledOnce()
  })

  it("turns runtime.lastError into a rejected promise", async () => {
    await expect(
      callExtensionCallback<void>(
        (callback) => callback(),
        () => ({ message: "permission denied" })
      )
    ).rejects.toThrow("permission denied")
  })

  it("rejects synchronous API errors", async () => {
    await expect(
      callExtensionCallback<void>(
        () => {
          throw new Error("missing callback API")
        },
        () => undefined
      )
    ).rejects.toThrow("missing callback API")
  })

  it("uses the tab supplied by Firefox's command event", async () => {
    const commandTab = { id: 42 }
    const query = vi.fn()

    await expect(
      resolveActiveTab(commandTab, query, () => undefined)
    ).resolves.toBe(commandTab)
    expect(query).not.toHaveBeenCalled()
  })

  it("queries through the callback API when a command has no tab", async () => {
    const activeTab = { id: 84 }

    await expect(
      resolveActiveTab(
        undefined,
        (callback) => callback([activeTab]),
        () => undefined
      )
    ).resolves.toBe(activeTab)
  })
})
