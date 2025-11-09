import { identifyIOC } from "../utility/utils";

/**
 * Creates a contextual button for a specific IOC type.
 * It displays either the VirusTotal or AbuseIPDB icon depending on the type.
 */
const getIconURL = (filename: string) => chrome.runtime.getURL(`assets/${filename}`)

export function createButton(ioc: string, onClick: () => void): HTMLButtonElement | null {
  const button = document.createElement("button")
  const type = identifyIOC(ioc)
  if (!type) return null

  const icon = type === "IP" ? "abuseipdb.png" : "virustotal.png"
  button.style.background = `url(${getIconURL(icon)})`
  button.style.backgroundSize = "cover"
  button.style.width = "25px"
  button.style.height = "25px"
  button.style.position = "absolute"
  button.style.zIndex = "2147483647" // stay above host popups/overlays
  button.style.border = "none"
  button.style.borderRadius = "4px"
  button.style.cursor = "pointer"
  button.id = "IOCButton_SOCx"

  button.addEventListener("mousedown", (event) => event.preventDefault())
  button.addEventListener("click", onClick)
  return button
}

export function createMagicButton(ioc: string, onClick: () => void): HTMLButtonElement {
  const button = document.createElement("button")
  button.style.background = `url(${getIconURL("icon.png")})`
  button.style.backgroundSize = "cover"
  button.style.width = "25px"
  button.style.height = "25px"
  button.style.position = "absolute"
  button.style.zIndex = "2147483647" // ensure visibility above modals
  button.style.border = "none"
  button.style.borderRadius = "4px"
  button.style.cursor = "pointer"
  button.style.backgroundColor = "#FFC107"
  button.id = "MagicButton_SOCx"

  button.addEventListener("mousedown", (event) => event.preventDefault())
  button.addEventListener("click", onClick)
  return button
}
