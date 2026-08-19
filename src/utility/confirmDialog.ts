// In-page confirmation dialog rendered by the content script. It mirrors the
// toast styling so that it stays recognisable as SOCx on any host page while
// keeping every style isolated with `all: initial` and `!important`.

import type { ConfirmRequest } from "./confirmBridge"

const DIALOG_ATTRIBUTE = "data-socx-confirm"
const MAX_Z_INDEX = "2147483647"
let dismissActiveDialog: (() => void) | null = null

const setImportantStyles = (
  element: HTMLElement,
  styles: Record<string, string>
): void => {
  Object.entries(styles).forEach(([property, value]) => {
    element.style.setProperty(property, value, "important")
  })
}

const isDarkDocument = (): boolean => {
  const usesDarkClass =
    document.documentElement.classList.contains("dark-mode") ||
    document.documentElement.classList.contains("dark") ||
    document.body?.classList.contains("dark-mode") ||
    document.body?.classList.contains("dark")
  if (usesDarkClass) return true
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
  )
}

const buildButton = (
  label: string,
  variant: "primary" | "ghost",
  dark: boolean
): HTMLButtonElement => {
  const button = document.createElement("button")
  button.type = "button"
  button.textContent = label
  setImportantStyles(button, {
    all: "initial",
    display: "inline-flex",
    "align-items": "center",
    "justify-content": "center",
    padding: "8px 16px",
    margin: "0",
    "border-radius": "999px",
    "font-family":
      "Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    "font-size": "13px",
    "font-weight": "600",
    cursor: "pointer",
    color: variant === "primary" ? "#111827" : dark ? "#f8fafc" : "#111827",
    "background-color": variant === "primary" ? "#f5c242" : "transparent",
    border:
      variant === "primary"
        ? "1px solid #f5c242"
        : `1px solid ${dark ? "rgba(255, 255, 255, 0.24)" : "rgba(17, 24, 39, 0.18)"}`,
    "pointer-events": "auto"
  })
  return button
}

export const showConfirmDialog = ({
  title,
  message,
  confirmLabel = "Continue",
  cancelLabel = "Cancel"
}: ConfirmRequest): Promise<boolean> => {
  if (typeof document === "undefined" || !document.documentElement) {
    return Promise.resolve(false)
  }

  // A pending dialog is cancelled instead of leaving its promise and keyboard
  // listener alive behind the replacement.
  dismissActiveDialog?.()

  const dark = isDarkDocument()

  return new Promise<boolean>((resolve) => {
    const backdrop = document.createElement("div")
    backdrop.setAttribute(DIALOG_ATTRIBUTE, "true")
    setImportantStyles(backdrop, {
      all: "initial",
      position: "fixed",
      inset: "0",
      "z-index": MAX_Z_INDEX,
      display: "flex",
      "align-items": "center",
      "justify-content": "center",
      padding: "16px",
      "background-color": "rgba(15, 23, 42, 0.45)",
      isolation: "isolate"
    })

    const panel = document.createElement("div")
    panel.setAttribute("role", "dialog")
    panel.setAttribute("aria-modal", "true")
    setImportantStyles(panel, {
      all: "initial",
      display: "flex",
      "flex-direction": "column",
      gap: "10px",
      width: "380px",
      "max-width": "calc(100vw - 32px)",
      padding: "18px",
      "box-sizing": "border-box",
      color: dark ? "#f8fafc" : "#111827",
      "background-color": dark
        ? "rgba(17, 24, 39, 0.98)"
        : "rgba(255, 255, 255, 0.99)",
      border: `1px solid ${dark ? "rgba(255, 255, 255, 0.16)" : "rgba(17, 24, 39, 0.14)"}`,
      "border-left": "4px solid #f5c242",
      "border-radius": "14px",
      "box-shadow": dark
        ? "0 24px 48px rgba(0, 0, 0, 0.55)"
        : "0 24px 48px rgba(15, 23, 42, 0.26)",
      "font-family":
        "Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    })

    const titleElement = document.createElement("p")
    titleElement.textContent = title
    setImportantStyles(titleElement, {
      all: "initial",
      display: "block",
      margin: "0",
      color: "inherit",
      "font-family": "inherit",
      "font-size": "15px",
      "font-weight": "600",
      "line-height": "1.3"
    })

    const messageElement = document.createElement("p")
    messageElement.textContent = message
    setImportantStyles(messageElement, {
      all: "initial",
      display: "block",
      margin: "0",
      color: "inherit",
      "font-family": "inherit",
      "font-size": "13px",
      "font-weight": "400",
      "line-height": "1.45",
      opacity: "0.85",
      "overflow-wrap": "anywhere"
    })

    const actions = document.createElement("div")
    setImportantStyles(actions, {
      all: "initial",
      display: "flex",
      "justify-content": "flex-end",
      gap: "8px",
      "margin-top": "4px"
    })

    const cancelButton = buildButton(cancelLabel, "ghost", dark)
    const confirmButton = buildButton(confirmLabel, "primary", dark)

    let settled = false
    const close = (confirmed: boolean) => {
      if (settled) return
      settled = true
      document.removeEventListener("keydown", onKeyDown, true)
      backdrop.remove()
      if (dismissActiveDialog === dismiss) {
        dismissActiveDialog = null
      }
      resolve(confirmed)
    }

    const dismiss = () => close(false)
    dismissActiveDialog = dismiss

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault()
        close(false)
      }
    }

    cancelButton.addEventListener("click", () => close(false))
    confirmButton.addEventListener("click", () => close(true))
    backdrop.addEventListener("click", (event) => {
      if (event.target === backdrop) close(false)
    })
    document.addEventListener("keydown", onKeyDown, true)

    actions.append(cancelButton, confirmButton)
    panel.append(titleElement, messageElement, actions)
    backdrop.appendChild(panel)
    ;(document.body ?? document.documentElement).appendChild(backdrop)
    confirmButton.focus?.()
  })
}
