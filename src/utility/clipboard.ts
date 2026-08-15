import { prepareIntelClipboardText } from "./clipboardSanitization"
import { showToast } from "./toast"

export type ClipboardWriteMethod = "clipboard-api" | "exec-command"

export type ClipboardWriteResult = {
  success: boolean
  method?: ClipboardWriteMethod
  error?: unknown
}

type ClipboardFeedbackOptions = {
  successMessage?: string
  errorMessage?: string
  onSuccess?: (result: ClipboardWriteResult) => void
  onError?: (result: ClipboardWriteResult) => void
  silent?: boolean
}

const writeWithExecCommand = (text: string): boolean => {
  if (typeof document === "undefined" || !document.body) return false

  const activeElement = document.activeElement as HTMLElement | null
  const inputSelection =
    activeElement instanceof HTMLInputElement ||
    activeElement instanceof HTMLTextAreaElement
      ? {
          start: activeElement.selectionStart,
          end: activeElement.selectionEnd
        }
      : null
  const selection = typeof window !== "undefined" ? window.getSelection() : null
  const selectedRanges = selection
    ? Array.from({ length: selection.rangeCount }, (_, index) =>
        selection.getRangeAt(index).cloneRange()
      )
    : []
  const textarea = document.createElement("textarea")
  textarea.value = text
  textarea.readOnly = true
  textarea.setAttribute("aria-hidden", "true")
  textarea.style.position = "fixed"
  textarea.style.top = "-1000px"
  textarea.style.opacity = "0"
  document.body.appendChild(textarea)

  try {
    textarea.focus()
    textarea.select()
    return typeof document.execCommand === "function"
      ? document.execCommand("copy")
      : false
  } finally {
    textarea.remove()
    activeElement?.focus?.()
    if (
      inputSelection &&
      inputSelection.start !== null &&
      inputSelection.end !== null
    ) {
      ;(
        activeElement as HTMLInputElement | HTMLTextAreaElement
      ).setSelectionRange(inputSelection.start, inputSelection.end)
    } else if (selection && selectedRanges.length > 0) {
      selection.removeAllRanges()
      selectedRanges.forEach((range) => selection.addRange(range))
    }
  }
}

const reportResult = (
  result: ClipboardWriteResult,
  options: ClipboardFeedbackOptions
): void => {
  if (options.silent) return
  if (result.success) {
    if (options.onSuccess) options.onSuccess(result)
    else showToast(options.successMessage ?? "✔️ Copied to clipboard")
    return
  }
  if (options.onError) options.onError(result)
  else
    showToast(
      options.errorMessage ?? "❌ Unable to copy to clipboard",
      "danger"
    )
}

export const writeClipboardText = async (
  text: string,
  options: ClipboardFeedbackOptions = {}
): Promise<ClipboardWriteResult> => {
  let primaryError: unknown
  try {
    if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) {
      throw new Error("Clipboard API unavailable")
    }
    await navigator.clipboard.writeText(text)
    const result: ClipboardWriteResult = {
      success: true,
      method: "clipboard-api"
    }
    reportResult(result, options)
    return result
  } catch (error) {
    primaryError = error
  }

  try {
    if (writeWithExecCommand(text)) {
      const result: ClipboardWriteResult = {
        success: true,
        method: "exec-command"
      }
      reportResult(result, options)
      return result
    }
  } catch (error) {
    primaryError = error
  }

  const result: ClipboardWriteResult = {
    success: false,
    error: primaryError
  }
  reportResult(result, options)
  return result
}

export const writeIntelClipboardText = async (
  text: string,
  options: ClipboardFeedbackOptions = {}
): Promise<ClipboardWriteResult> =>
  writeClipboardText(await prepareIntelClipboardText(text), options)
