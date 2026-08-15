import type { ResolvedServicePage } from "./servicePageAdapters"

export type ServiceCopyButtonController = {
  remove: () => void
}

type ButtonState = "idle" | "copying" | "success" | "error"

const COPY_ICON = `
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <path d="M8 7.75A2.75 2.75 0 0 1 10.75 5h6.5A2.75 2.75 0 0 1 20 7.75v8.5A2.75 2.75 0 0 1 17.25 19h-6.5A2.75 2.75 0 0 1 8 16.25v-8.5Z" />
    <path d="M15.75 5v-.25A2.75 2.75 0 0 0 13 2H6.75A2.75 2.75 0 0 0 4 4.75V13a2.75 2.75 0 0 0 2.75 2.75H8" />
  </svg>
`

const parseRgb = (value: string): [number, number, number, number] | null => {
  const match = value.match(
    /rgba?\(\s*(\d+)[,\s]+(\d+)[,\s]+(\d+)(?:\s*[,/]\s*([\d.]+))?/i
  )
  return match
    ? [
        Number(match[1]),
        Number(match[2]),
        Number(match[3]),
        match[4] === undefined ? 1 : Number(match[4])
      ]
    : null
}

const isDarkPage = (targetDocument: Document): boolean => {
  const candidates = [
    targetDocument.body,
    targetDocument.querySelector("main"),
    targetDocument.documentElement
  ].filter(Boolean) as Element[]

  for (const candidate of candidates) {
    const rgb = parseRgb(getComputedStyle(candidate).backgroundColor)
    if (!rgb) continue
    const [red, green, blue, alpha] = rgb
    if (alpha === 0) continue
    return red * 0.299 + green * 0.587 + blue * 0.114 < 145
  }
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false
}

const hostAccent = (targetDocument: Document): string => {
  const candidate = targetDocument.querySelector(
    "main a, main button, [role='main'] a, [role='main'] button, a"
  )
  const color = candidate ? getComputedStyle(candidate).color : ""
  return /^(?:rgb|hsl|#)/i.test(color) ? color : "#f5c242"
}

const setHostStyles = (host: HTMLElement, targetDocument: Document): void => {
  const dark = isDarkPage(targetDocument)
  const styles: Record<string, string> = {
    all: "initial",
    position: "fixed",
    right: "12px",
    bottom: "12px",
    "z-index": "2147483646",
    display: "block",
    margin: "0",
    padding: "0",
    width: "auto",
    height: "auto",
    "max-width": "calc(100vw - 24px)",
    "pointer-events": "auto",
    "box-sizing": "border-box",
    "font-family":
      getComputedStyle(targetDocument.body).fontFamily ||
      "system-ui, sans-serif",
    "--socx-page-accent": hostAccent(targetDocument),
    "--socx-surface": dark
      ? "rgba(17, 24, 39, 0.94)"
      : "rgba(255, 255, 255, 0.94)",
    "--socx-text": dark ? "#f8fafc" : "#172033",
    "--socx-border": dark
      ? "rgba(255, 255, 255, 0.2)"
      : "rgba(15, 23, 42, 0.18)",
    "--socx-shadow": dark ? "rgba(0, 0, 0, 0.42)" : "rgba(15, 23, 42, 0.2)"
  }
  Object.entries(styles).forEach(([property, value]) =>
    host.style.setProperty(property, value, "important")
  )
}

export const mountServiceCopyButton = ({
  page,
  onCopy,
  targetDocument = document
}: {
  page: ResolvedServicePage
  onCopy: () => Promise<boolean>
  targetDocument?: Document
}): ServiceCopyButtonController => {
  targetDocument.querySelector("[data-socx-service-copy]")?.remove()

  const host = targetDocument.createElement("div")
  host.id = "socx-service-copy"
  host.setAttribute("data-socx-service-copy", page.adapter.id)
  setHostStyles(host, targetDocument)

  const shadow = host.attachShadow({ mode: "open" })
  const style = targetDocument.createElement("style")
  style.textContent = `
    :host { color-scheme: light dark; }
    *, *::before, *::after { box-sizing: border-box; }
    button {
      appearance: none;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      min-height: 38px;
      max-width: 100%;
      margin: 0;
      padding: 5px 10px 5px 5px;
      border: 1px solid var(--socx-border);
      border-top-color: color-mix(in srgb, var(--socx-page-accent) 45%, var(--socx-border));
      border-radius: 999px;
      color: var(--socx-text);
      background: var(--socx-surface);
      box-shadow: 0 10px 28px var(--socx-shadow);
      backdrop-filter: blur(16px) saturate(125%);
      -webkit-backdrop-filter: blur(16px) saturate(125%);
      font-family: inherit;
      font-size: 12px;
      font-weight: 600;
      line-height: 1.2;
      letter-spacing: 0.01em;
      cursor: pointer;
      transition: transform 150ms ease, border-color 150ms ease, box-shadow 150ms ease;
    }
    button:hover {
      border-color: var(--socx-page-accent);
      box-shadow: 0 12px 32px var(--socx-shadow);
      transform: translateY(-1px);
    }
    button:active { transform: translateY(0) scale(0.98); }
    button:focus-visible {
      outline: 2px solid var(--socx-page-accent);
      outline-offset: 2px;
    }
    button:disabled { cursor: wait; opacity: 0.72; transform: none; }
    .brand {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 41px;
      height: 28px;
      padding: 0 7px;
      border-radius: 999px;
      color: #241b02;
      background: #f5c242;
      font-family: inherit;
      font-size: 10px;
      font-weight: 800;
      line-height: 1;
      letter-spacing: 0.08em;
    }
    .icon { display: inline-flex; color: var(--socx-page-accent); }
    .icon svg {
      width: 17px;
      height: 17px;
      fill: none;
      stroke: currentColor;
      stroke-width: 1.8;
      stroke-linecap: round;
      stroke-linejoin: round;
    }
    .label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    @media (max-width: 480px) {
      button { gap: 6px; padding-right: 7px; }
      .label { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }
    }
    @media (prefers-reduced-motion: reduce) {
      button { transition: none; }
    }
  `

  const button = targetDocument.createElement("button")
  button.type = "button"
  button.title = `Copy formatted ${page.adapter.label} data with SOCx`
  button.setAttribute("aria-label", button.title)

  const brand = targetDocument.createElement("span")
  brand.className = "brand"
  brand.textContent = "SOCx"
  const icon = targetDocument.createElement("span")
  icon.className = "icon"
  icon.innerHTML = COPY_ICON
  const label = targetDocument.createElement("span")
  label.className = "label"

  const setState = (state: ButtonState) => {
    button.disabled = state === "copying"
    label.textContent =
      state === "copying"
        ? "Formatting…"
        : state === "success"
          ? "Copied"
          : state === "error"
            ? "Copy failed"
            : `Copy ${page.adapter.label}`
  }
  setState("idle")

  button.append(brand, icon, label)
  button.addEventListener("click", async (event) => {
    event.preventDefault()
    event.stopPropagation()
    setState("copying")
    let state: ButtonState = "error"
    try {
      state = (await onCopy()) ? "success" : "error"
    } catch {
      state = "error"
    }
    setState(state)
    window.setTimeout(() => {
      if (host.isConnected) setState("idle")
    }, 1_400)
  })

  shadow.append(style, button)
  ;(targetDocument.body ?? targetDocument.documentElement).appendChild(host)

  return { remove: () => host.remove() }
}
