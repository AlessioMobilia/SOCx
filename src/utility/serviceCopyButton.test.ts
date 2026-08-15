import { afterEach, describe, expect, it, vi } from "vitest"

import { mountServiceCopyButton } from "./serviceCopyButton"
import { resolveServicePage } from "./servicePageAdapters"

describe("service page copy button", () => {
  afterEach(() => {
    document.body.innerHTML = ""
    vi.restoreAllMocks()
  })

  it("uses an isolated fixed control without changing the host layout", () => {
    document.body.innerHTML = "<main><a href='#'>Host action</a></main>"
    const page = resolveServicePage("https://stat.ripe.net/resource/8.8.8.8")!

    mountServiceCopyButton({ page, onCopy: vi.fn(async () => true) })

    const host = document.querySelector<HTMLElement>("[data-socx-service-copy]")
    const button = host?.shadowRoot?.querySelector("button")
    expect(host?.style.position).toBe("fixed")
    expect(host?.style.getPropertyPriority("position")).toBe("important")
    expect(host?.style.bottom).toBe("12px")
    expect(host?.style.zIndex).toBe("2147483646")
    expect(button?.textContent).toContain("SOCx")
    expect(button?.textContent).toContain("Copy RIPEstat")
  })

  it("runs the copy action once and exposes progress feedback", async () => {
    const onCopy = vi.fn(async () => true)
    const page = resolveServicePage("https://crt.sh/?q=example.com")!
    mountServiceCopyButton({ page, onCopy })
    const button = document
      .querySelector<HTMLElement>("[data-socx-service-copy]")
      ?.shadowRoot?.querySelector<HTMLButtonElement>("button")

    button?.click()
    await vi.waitFor(() => expect(onCopy).toHaveBeenCalledTimes(1))
    expect(button?.textContent).toContain("Copied")
  })
})
