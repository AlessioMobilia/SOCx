import { afterEach, describe, expect, it, vi } from "vitest"

import { writeClipboardText } from "./clipboard"

describe("clipboard writer", () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("uses the Clipboard API when it is available", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText }
    })

    const result = await writeClipboardText("IOC", { silent: true })

    expect(result).toEqual({ success: true, method: "clipboard-api" })
    expect(writeText).toHaveBeenCalledWith("IOC")
  })

  it("falls back to execCommand when the Clipboard API fails", async () => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: vi.fn().mockRejectedValue(new Error("denied")) }
    })
    const execCommand = vi.fn().mockReturnValue(true)
    Object.defineProperty(document, "execCommand", {
      configurable: true,
      value: execCommand
    })

    const result = await writeClipboardText("IOC", { silent: true })

    expect(result).toEqual({ success: true, method: "exec-command" })
    expect(execCommand).toHaveBeenCalledWith("copy")
  })
})
