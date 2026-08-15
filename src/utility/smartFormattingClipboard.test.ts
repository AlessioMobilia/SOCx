import { afterEach, describe, expect, it, vi } from "vitest"

import { copySmartFormattedText } from "./smartFormattingClipboard"

describe("smart formatting clipboard feedback", () => {
  afterEach(() => {
    document.body.innerHTML = ""
    vi.restoreAllMocks()
  })

  it("copies the formatted text and displays a success toast", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText }
    })

    const result = await copySmartFormattedText(
      "Device:  WS-FIN-023\nProcess: WINWORD.EXE"
    )

    expect(result.success).toBe(true)
    expect(writeText).toHaveBeenCalledWith(
      "Device:  WS-FIN-023\nProcess: WINWORD.EXE"
    )
    expect(document.querySelector("[data-socx-toast]")?.textContent).toContain(
      "Smart-formatted selection copied"
    )
  })

  it("displays a warning toast when the selection has no formatted data", async () => {
    const result = await copySmartFormattedText("   ")

    expect(result).toMatchObject({ success: false, error: "No formatted text" })
    expect(
      document.querySelector('[data-socx-toast="warning"]')?.textContent
    ).toContain("No key/value data found")
  })
})
