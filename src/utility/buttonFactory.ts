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
  background: string
  border: string
  color: string
  icon: keyof typeof ICONS
}

const THEMES: Record<"virustotal" | "abuse" | "magic", ButtonTheme> = {
  virustotal: {
    background: "rgba(37, 100, 235, 1)",
    border: "rgba(59, 130, 246, 0.9)",
    color: "#06182eff",
    icon: "virustotal"
  },
  abuse: {
    background: "rgba(239, 68, 68, 1)",
    border: "rgba(248, 113, 113, 0.9)",
    color: "#300c0cff",
    icon: "abuse"
  },
  magic: {
    background: "rgba(245, 194, 66, 1)",
    border: "rgba(245, 194, 66, 0.9)",
    color: "#2b1b00",
    icon: "magic"
  }
}

const applyBaseStyling = (button: HTMLButtonElement, theme: ButtonTheme, label: string) => {
  button.type = "button"
  button.innerHTML = ICONS[theme.icon]

  // dimensioni / layout
  button.style.width = "30px"
  button.style.height = "30px"
  button.style.position = "absolute"
  button.style.zIndex = "2147483647"
  button.style.borderRadius = "8px"
  button.style.display = "inline-flex"
  button.style.alignItems = "center"
  button.style.justifyContent = "center"
  button.style.padding = "0"
  button.style.cursor = "pointer"

  // stile FLAT (no shadow, no blur), manteniamo i colori originali
  button.style.border = `1px solid ${theme.border}`
  button.style.background = theme.background
  button.style.color = theme.color

  // transizioni leggere
  button.style.transition = [
    "transform 0.16s ease-out",
    "background-color 0.16s ease-out",
    "border-color 0.16s ease-out",
    "opacity 0.16s ease-out"
  ].join(", ")

  // accessibilità
  button.setAttribute("aria-label", label)
  button.title = label
  button.style.outline = "none"

  // SVG leggermente ridimensionato
  const svg = button.querySelector("svg")
  if (svg) {
    svg.setAttribute("width", "18")
    svg.setAttribute("height", "18")
    ;(svg as SVGElement).style.opacity = "0.95"
  }

  // stato di base
  button.style.opacity = "0.96"

  // hover (flat: nessuna ombra, solo micro movimento + opacity)
  button.addEventListener("mouseenter", () => {
    button.style.transform = "translateY(-1px) scale(1.02)"
    button.style.opacity = "1"
  })

  button.addEventListener("mouseleave", () => {
    button.style.transform = "translateY(0) scale(1)"
    button.style.opacity = "0.96"
  })

  // active (click) – leggero "press"
  button.addEventListener("mousedown", () => {
    button.style.transform = "translateY(0px) scale(0.96)"
    button.style.opacity = "0.9"
  })
  button.addEventListener("mouseup", () => {
    button.style.transform = "translateY(-1px) scale(1.02)"
    button.style.opacity = "1"
  })

  // focus per tastiera (anello sobrio)
  button.addEventListener("focus", () => {
    button.style.boxShadow = "0 0 0 2px rgba(148, 163, 184, 0.7)"
  })
  button.addEventListener("blur", () => {
    button.style.boxShadow = "none"
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
