import { afterEach, describe, expect, it, vi } from "vitest"

import { showToast } from "./toast"

describe("toast rendering", () => {
  afterEach(() => {
    document.querySelector('[data-socx-toast-container="true"]')?.remove()
    document.documentElement.classList.remove("dark", "dark-mode")
    document.body.classList.remove("dark", "dark-mode")
    vi.useRealTimers()
  })

  it("renders an isolated, responsive toast above extension overlays", () => {
    showToast("Copied")

    const container = document.querySelector<HTMLElement>(
      '[data-socx-toast-container="true"]'
    )
    const toast = container?.querySelector<HTMLElement>("[data-socx-toast]")
    const closeButton = toast?.querySelector<HTMLButtonElement>("button")

    expect(container?.style.zIndex).toBe("2147483647")
    expect(container?.style.width).toBe("380px")
    expect(container?.style.maxWidth).toContain("100vw - 24px")
    expect(container?.style.getPropertyPriority("position")).toBe("important")
    expect(toast?.style.backgroundColor).not.toBe("")
    expect(toast?.getAttribute("role")).toBe("status")
    expect(closeButton?.getAttribute("aria-label")).toBe("Close notification")
  })

  it("uses assertive semantics for errors and caps the visible stack", () => {
    showToast("Failure", "danger")
    expect(
      document.querySelector('[data-socx-toast="danger"]')?.getAttribute("role")
    ).toBe("alert")

    for (let index = 0; index < 5; index += 1) {
      showToast(`Message ${index}`)
    }
    expect(document.querySelectorAll("[data-socx-toast]")).toHaveLength(4)
  })

  it("removes a toast and its empty container from the close button", () => {
    vi.useFakeTimers()
    showToast("Dismiss me")

    document.querySelector<HTMLButtonElement>(".socx-toast__close")?.click()
    vi.advanceTimersByTime(181)

    expect(document.querySelector("[data-socx-toast]")).toBeNull()
    expect(document.querySelector(`[data-socx-toast-container]`)).toBeNull()
  })
})
