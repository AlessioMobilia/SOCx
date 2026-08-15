export type ToastVariant = "primary" | "success" | "danger" | "warning" | "info"

const CONTAINER_ATTRIBUTE = "data-socx-toast-container"
const TOAST_ATTRIBUTE = "data-socx-toast"
const MAX_VISIBLE_TOASTS = 4
const MAX_Z_INDEX = "2147483647"

const VARIANT_COLORS: Record<ToastVariant, string> = {
  primary: "#f5c242",
  success: "#34d399",
  danger: "#f87171",
  warning: "#fbbf24",
  info: "#38bdf8"
}

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

const getToastContainer = (): HTMLElement => {
  const existing = document.querySelector<HTMLElement>(
    `[${CONTAINER_ATTRIBUTE}="true"]`
  )
  if (existing) return existing

  const container = document.createElement("div")
  container.id = "socx-toast-container"
  container.setAttribute(CONTAINER_ATTRIBUTE, "true")
  container.setAttribute("aria-live", "polite")
  container.setAttribute("aria-relevant", "additions removals")
  setImportantStyles(container, {
    all: "initial",
    position: "fixed",
    right: "12px",
    bottom: document.querySelector("[data-socx-service-copy]")
      ? "64px"
      : "12px",
    "z-index": MAX_Z_INDEX,
    display: "flex",
    "flex-direction": "column",
    "align-items": "flex-end",
    gap: "10px",
    width: "380px",
    "max-width": "calc(100vw - 24px)",
    "max-height": "calc(100vh - 24px)",
    margin: "0",
    padding: "0",
    "box-sizing": "border-box",
    "pointer-events": "none",
    isolation: "isolate"
  })
  ;(document.body ?? document.documentElement).appendChild(container)
  return container
}

const removeContainerWhenEmpty = (container: HTMLElement): void => {
  if (!container.querySelector(`[${TOAST_ATTRIBUTE}]`)) container.remove()
}

export const showToast = (
  message: string,
  variant: ToastVariant = "primary"
): (() => void) => {
  if (typeof document === "undefined" || !document.documentElement) {
    return () => undefined
  }

  const resolvedVariant = VARIANT_COLORS[variant] ? variant : "primary"
  const accent = VARIANT_COLORS[resolvedVariant]
  const dark = isDarkDocument()
  const container = getToastContainer()
  const existingToasts = Array.from(
    container.querySelectorAll<HTMLElement>(`[${TOAST_ATTRIBUTE}]`)
  )
  existingToasts
    .slice(0, Math.max(0, existingToasts.length - MAX_VISIBLE_TOASTS + 1))
    .forEach((toast) => toast.remove())

  const toast = document.createElement("div")
  toast.className = `socx-toast socx-toast--${resolvedVariant}`
  toast.setAttribute(TOAST_ATTRIBUTE, resolvedVariant)
  toast.setAttribute("role", resolvedVariant === "danger" ? "alert" : "status")
  toast.setAttribute("aria-atomic", "true")
  setImportantStyles(toast, {
    all: "initial",
    position: "relative",
    display: "flex",
    "align-items": "center",
    gap: "10px",
    width: "100%",
    "min-height": "48px",
    margin: "0",
    padding: "11px 10px 11px 14px",
    "box-sizing": "border-box",
    color: dark ? "#f8fafc" : "#111827",
    "background-color": dark
      ? "rgba(17, 24, 39, 0.97)"
      : "rgba(255, 255, 255, 0.98)",
    border: `1px solid ${dark ? "rgba(255, 255, 255, 0.16)" : "rgba(17, 24, 39, 0.14)"}`,
    "border-left": `4px solid ${accent}`,
    "border-radius": "12px",
    "box-shadow": dark
      ? "0 16px 36px rgba(0, 0, 0, 0.48)"
      : "0 16px 36px rgba(15, 23, 42, 0.22)",
    "font-family":
      "Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    "font-size": "14px",
    "font-weight": "500",
    "line-height": "1.4",
    opacity: "0",
    transform: "translateY(8px) scale(0.98)",
    transition: "opacity 160ms ease, transform 160ms ease",
    "pointer-events": "auto",
    isolation: "isolate"
  })

  const messageElement = document.createElement("div")
  messageElement.className = "socx-toast__message"
  messageElement.textContent = message
  setImportantStyles(messageElement, {
    all: "initial",
    display: "block",
    flex: "1 1 auto",
    "min-width": "0",
    margin: "0",
    padding: "0",
    color: "inherit",
    "font-family": "inherit",
    "font-size": "inherit",
    "font-weight": "inherit",
    "line-height": "inherit",
    "overflow-wrap": "anywhere",
    "white-space": "normal"
  })

  const closeButton = document.createElement("button")
  closeButton.className = "socx-toast__close"
  closeButton.type = "button"
  closeButton.setAttribute("aria-label", "Close notification")
  closeButton.textContent = "×"
  setImportantStyles(closeButton, {
    all: "initial",
    display: "inline-flex",
    "align-items": "center",
    "justify-content": "center",
    flex: "0 0 30px",
    width: "30px",
    height: "30px",
    margin: "0",
    padding: "0",
    color: "inherit",
    "background-color": "transparent",
    border: "0",
    "border-radius": "999px",
    "font-family": "inherit",
    "font-size": "22px",
    "font-weight": "400",
    "line-height": "1",
    cursor: "pointer",
    opacity: "0.72",
    "pointer-events": "auto"
  })

  let autoDismissTimer: ReturnType<typeof setTimeout> | undefined
  let dismissed = false
  const dismiss = () => {
    if (dismissed) return
    dismissed = true
    if (autoDismissTimer) clearTimeout(autoDismissTimer)
    setImportantStyles(toast, {
      opacity: "0",
      transform: "translateY(6px) scale(0.98)"
    })
    setTimeout(() => {
      toast.remove()
      removeContainerWhenEmpty(container)
    }, 180)
  }
  const scheduleDismiss = (delay: number) => {
    if (autoDismissTimer) clearTimeout(autoDismissTimer)
    autoDismissTimer = setTimeout(dismiss, delay)
  }

  closeButton.addEventListener("click", dismiss)
  toast.addEventListener("pointerenter", () => {
    if (autoDismissTimer) clearTimeout(autoDismissTimer)
  })
  toast.addEventListener("pointerleave", () => scheduleDismiss(2_000))
  toast.addEventListener("focusin", () => {
    if (autoDismissTimer) clearTimeout(autoDismissTimer)
  })
  toast.addEventListener("focusout", () => scheduleDismiss(2_000))
  toast.append(messageElement, closeButton)
  container.appendChild(toast)

  const reveal = () =>
    setImportantStyles(toast, {
      opacity: "1",
      transform: "translateY(0) scale(1)"
    })
  if (typeof requestAnimationFrame === "function") requestAnimationFrame(reveal)
  else setTimeout(reveal, 0)

  scheduleDismiss(resolvedVariant === "danger" ? 6_000 : 4_000)
  return dismiss
}
