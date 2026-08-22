import { describe, expect, it, vi } from "vitest"

import { OPEN_QUERY_PALETTE_MESSAGE } from "../utility/query/paletteBridge"
import { openQueryPaletteFromMenu } from "./query-palette-menu"

describe("query palette context-menu launch", () => {
  it("opens the palette in the current tab", async () => {
    const openWorkspace = vi.fn()
    const sendMessage = vi.fn((_tabId, _message, callback) =>
      callback({ opened: true })
    )

    await expect(
      openQueryPaletteFromMenu(42, ["8.8.8.8"], undefined, {
        sendMessage,
        getLastError: () => undefined,
        openWorkspace
      })
    ).resolves.toBe("palette")
    expect(sendMessage).toHaveBeenCalledWith(
      42,
      {
        name: OPEN_QUERY_PALETTE_MESSAGE,
        body: { indicators: ["8.8.8.8"], templateKey: undefined }
      },
      expect.any(Function)
    )
    expect(openWorkspace).not.toHaveBeenCalled()
  })

  it("falls back to Query workspace when the content script is unavailable", async () => {
    const openWorkspace = vi.fn(async () => undefined)
    const sendMessage = vi.fn((_tabId, _message, callback) => callback())

    await expect(
      openQueryPaletteFromMenu(42, ["evil.example"], undefined, {
        sendMessage,
        getLastError: () => ({ message: "Receiving end does not exist" }),
        openWorkspace
      })
    ).resolves.toBe("workspace")
    expect(openWorkspace).toHaveBeenCalledWith(["evil.example"])
  })

  it("uses the fallback when the menu has no tab id", async () => {
    const openWorkspace = vi.fn(async () => undefined)
    const sendMessage = vi.fn()

    await expect(
      openQueryPaletteFromMenu(undefined, [], undefined, {
        sendMessage,
        getLastError: () => undefined,
        openWorkspace
      })
    ).resolves.toBe("workspace")
    expect(sendMessage).not.toHaveBeenCalled()
  })

  it("uses the fallback when sending fails synchronously", async () => {
    const openWorkspace = vi.fn(async () => undefined)

    await expect(
      openQueryPaletteFromMenu(42, [], undefined, {
        sendMessage: () => {
          throw new Error("invalid tab")
        },
        getLastError: () => undefined,
        openWorkspace
      })
    ).resolves.toBe("workspace")
    expect(openWorkspace).toHaveBeenCalledOnce()
  })

  it("falls back when the content script reports that no palette opened", async () => {
    const openWorkspace = vi.fn(async () => undefined)
    const sendMessage = vi.fn((_tabId, _message, callback) =>
      callback({ opened: false })
    )

    await expect(
      openQueryPaletteFromMenu(42, [], "source::pack::query", {
        sendMessage,
        getLastError: () => undefined,
        openWorkspace
      })
    ).resolves.toBe("workspace")
    expect(openWorkspace).toHaveBeenCalledOnce()
  })
})
