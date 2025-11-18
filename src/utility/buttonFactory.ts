import { identifyIOC } from "../utility/utils"

const ICONS = {
  virustotal: `
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
      <path stroke-linecap="round" stroke-linejoin="round"
        d="M12 9v3m0 3h.01M9.401 3.003a3 3 0 00-2.12.879L4.879 6.284a2.25 2.25 0 00-.659 1.59V11.25a9 9 0 005.211 8.153l1.528.636a2.25 2.25 0 001.724 0l1.528-.636A9 9 0 0019.78 11.25V7.875a2.25 2.25 0 00-.659-1.59L16.72 3.882a3 3 0 00-2.12-.879H9.4z" />
    </svg>
  `,
  abuse: `
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
      <path stroke-linecap="round" stroke-linejoin="round"
        d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  `,
  magic: `
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
      <path stroke-linecap="round" stroke-linejoin="round"
        d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
    </svg>
  `
} as const

type ButtonTheme = {
  surface: string
  surfaceHover: string
  surfaceActive: string
  border: string
  borderHover: string
  accent: string
  focusRing: string
  glow: string
  icon: keyof typeof ICONS
}

const THEMES: Record<"virustotal" | "abuse" | "magic", ButtonTheme> = {
  virustotal: {
    surface: "linear-gradient(135deg, rgba(10,16,30,0.94), rgba(33,51,92,0.82))",
    surfaceHover: "linear-gradient(135deg, rgba(15,24,44,0.96), rgba(45,70,120,0.88))",
    surfaceActive: "linear-gradient(135deg, rgba(8,13,24,0.92), rgba(29,47,86,0.78))",
    border: "rgba(120, 156, 236, 0.45)",
    borderHover: "rgba(120, 156, 236, 0.85)",
    accent: "#9cc7ff",
    focusRing: "rgba(120, 156, 236, 0.55)",
    glow: "rgba(10, 16, 30, 0.65)",
    icon: "virustotal"
  },
  abuse: {
    surface: "linear-gradient(135deg, rgba(22,8,12,0.94), rgba(56,20,30,0.82))",
    surfaceHover: "linear-gradient(135deg, rgba(30,10,14,0.95), rgba(68,24,36,0.9))",
    surfaceActive: "linear-gradient(135deg, rgba(18,6,10,0.92), rgba(46,16,26,0.78))",
    border: "rgba(248, 113, 113, 0.4)",
    borderHover: "rgba(248, 113, 113, 0.72)",
    accent: "#f87171",
    focusRing: "rgba(248, 113, 113, 0.5)",
    glow: "rgba(22, 8, 12, 0.7)",
    icon: "abuse"
  },
  magic: {
    surface: "linear-gradient(135deg, rgba(26,18,6,0.94), rgba(56,41,12,0.85))",
    surfaceHover: "linear-gradient(135deg, rgba(30,22,8,0.96), rgba(68,52,16,0.9))",
    surfaceActive: "linear-gradient(135deg, rgba(18,12,4,0.92), rgba(48,34,10,0.78))",
    border: "rgba(245, 194, 66, 0.45)",
    borderHover: "rgba(245, 194, 66, 0.8)",
    accent: "#f5c242",
    focusRing: "rgba(245, 194, 66, 0.55)",
    glow: "rgba(26, 18, 6, 0.65)",
    icon: "magic"
  }
}

const applyBaseStyling = (button: HTMLButtonElement, theme: ButtonTheme, label: string) => {
  button.type = "button"
  button.innerHTML = ICONS[theme.icon]

  // dimensioni / layout
  button.style.width = "36px"
  button.style.height = "36px"
  button.style.position = "absolute"
  button.style.zIndex = "2147483647"
  button.style.borderRadius = "16px"
  button.style.display = "inline-flex"
  button.style.alignItems = "center"
  button.style.justifyContent = "center"
  button.style.padding = "0"
  button.style.cursor = "pointer"
  button.style.fontFamily = "'Inter', system-ui, -apple-system, BlinkMacSystemFont, sans-serif"
  button.style.boxSizing = "border-box"
  button.style.backdropFilter = "blur(18px)"
  button.style.setProperty("-webkit-backdrop-filter", "blur(18px)")
  button.style.letterSpacing = "0.08em"
  button.style.textTransform = "uppercase"
  button.style.fontSize = "10px"
  button.style.fontWeight = "600"

  // nuova superficie glass + accenti SOCx
  button.style.border = `1px solid ${theme.border}`
  button.style.background = theme.surface
  button.style.color = theme.accent
  button.style.boxShadow = `0 15px 35px ${theme.glow}`

  // transizioni leggere
  button.style.transition = [
    "transform 0.16s ease-out",
    "background-color 0.16s ease-out",
    "border-color 0.16s ease-out",
    "opacity 0.16s ease-out",
    "box-shadow 0.2s ease-out",
    "background 0.2s ease-out"
  ].join(", ")

  // accessibilità
  button.setAttribute("aria-label", label)
  button.title = label
  button.style.outline = "none"

  // SVG leggermente ridimensionato
  const svg = button.querySelector("svg")
  if (svg) {
    svg.setAttribute("width", "17")
    svg.setAttribute("height", "17")
    ;(svg as SVGElement).style.opacity = "0.92"
  }

  // stato di base
  button.style.opacity = "0.96"

  type VisualState = "base" | "hover" | "active"
  let state: VisualState = "base"
  let isFocused = false

  const applyShadow = () => {
    const shadow =
      state === "active"
        ? `0 8px 24px ${theme.glow}`
        : state === "hover"
        ? `0 18px 42px ${theme.glow}`
        : `0 15px 35px ${theme.glow}`
    button.style.boxShadow = isFocused ? `${shadow}, 0 0 0 2px ${theme.focusRing}` : shadow
  }

  const setState = (next: VisualState) => {
    state = next
    if (state === "hover") {
      button.style.background = theme.surfaceHover
      button.style.borderColor = theme.borderHover
      button.style.opacity = "1"
      button.style.transform = "translateY(-2px) scale(1.03)"
    } else if (state === "active") {
      button.style.background = theme.surfaceActive
      button.style.borderColor = theme.borderHover
      button.style.opacity = "0.92"
      button.style.transform = "translateY(0px) scale(0.96)"
    } else {
      button.style.background = theme.surface
      button.style.borderColor = theme.border
      button.style.opacity = "0.96"
      button.style.transform = "translateY(0) scale(1)"
    }
    applyShadow()
  }

  setState("base")

  // hover con micro movimento e glow coerente col resto dell'estensione
  button.addEventListener("mouseenter", () => setState("hover"))

  button.addEventListener("mouseleave", () => setState("base"))

  // active (click) – leggero "press"
  button.addEventListener("mousedown", () => setState("active"))
  button.addEventListener("mouseup", () => setState("hover"))

  // focus per tastiera (anello sobrio)
  button.addEventListener("focus", () => {
    isFocused = true
    applyShadow()
  })
  button.addEventListener("blur", () => {
    isFocused = false
    applyShadow()
  })
}

export function createButton(ioc: string, onClick: () => void): HTMLButtonElement | null {
  const button = document.createElement("button")
  const type = identifyIOC(ioc)

  if (!type) {
    return null
  }

  const theme = type === "IP" ? THEMES.abuse : THEMES.virustotal
  const label = type === "IP" ? "AbuseIPDB" : "VirusTotal"

  applyBaseStyling(button, theme, label)
  button.id = "IOCButton_SOCx"

  // evita text selection ecc. mantenendo il feeling di click
  button.addEventListener("mousedown", (event) => event.preventDefault())
  button.addEventListener("click", onClick)

  return button
}

export function createMagicButton(ioc: string, onClick: () => void): HTMLButtonElement {
  const button = document.createElement("button")
  applyBaseStyling(button, THEMES.magic, "Magic IOC launch")
  button.id = "MagicButton_SOCx"

  button.addEventListener("mousedown", (event) => event.preventDefault())
  button.addEventListener("click", onClick)

  return button
}
