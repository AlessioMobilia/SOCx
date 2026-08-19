// Background side of the in-page confirmation used before a bulk tab opening.
// The dialog itself lives in the content script, so restricted pages (store
// pages, PDF viewers, about: URLs) simply do not answer and the caller decides
// how to proceed.

export const SOCX_CONFIRM_MESSAGE = "socx-confirm"

export type ConfirmRequest = {
  title: string
  message: string
  confirmLabel?: string
  cancelLabel?: string
}

export const DEFAULT_CONFIRM_TIMEOUT_MS = 4_000

export const requestTabConfirmation = (
  tabId: number | undefined,
  request: ConfirmRequest,
  timeoutMs = DEFAULT_CONFIRM_TIMEOUT_MS
): Promise<boolean | null> => {
  if (typeof tabId !== "number" || !chrome.tabs?.sendMessage) {
    return Promise.resolve(null)
  }

  return new Promise((resolve) => {
    let settled = false
    const settle = (value: boolean | null) => {
      if (settled) return
      settled = true
      resolve(value)
    }

    const timer = setTimeout(() => settle(null), timeoutMs)

    try {
      chrome.tabs.sendMessage(
        tabId,
        { name: SOCX_CONFIRM_MESSAGE, body: request },
        (response) => {
          clearTimeout(timer)
          // No content script on the page: the caller falls back to its default.
          if (chrome.runtime.lastError) {
            settle(null)
            return
          }
          settle(
            typeof response?.confirmed === "boolean" ? response.confirmed : null
          )
        }
      )
    } catch (error) {
      clearTimeout(timer)
      console.debug("Unable to request an in-page confirmation:", error)
      settle(null)
    }
  })
}
