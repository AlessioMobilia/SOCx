import { writeClipboardText } from "./clipboard"
import { showToast } from "./toast"

export type SmartFormattingCopyResult = {
  success: boolean
  formatted: string
  error?: string
}

export const copySmartFormattedText = async (
  formattedText: string
): Promise<SmartFormattingCopyResult> => {
  const formatted = formattedText.trim()
  if (!formatted) {
    showToast("No key/value data found in the selection", "warning")
    return {
      success: false,
      formatted: "",
      error: "No formatted text"
    }
  }

  const result = await writeClipboardText(formattedText, {
    successMessage: "✔️ Smart-formatted selection copied",
    errorMessage: "❌ Unable to copy the smart-formatted selection"
  })

  return {
    success: result.success,
    formatted,
    ...(result.success ? {} : { error: "Clipboard write failed" })
  }
}
