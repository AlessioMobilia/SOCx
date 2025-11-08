import type { PlasmoCSConfig } from "plasmo"
import { showToast } from "../utility/utils"

export const config: PlasmoCSConfig = {
  matches: ["https://www.abuseipdb.com/check/*"],
  all_frames: true
}

// Extract and format information from the page
function extractAndFormatInfo(): string | null {
  const container = document.querySelector(".col-md-6 .well")
  if (!container) return null

  const getText = (selector: string): string =>
    container.querySelector(selector)?.textContent?.replace(/\s+/g, " ").trim() || "N/A"

  const getCellText = (cell: Element | null): string => {
    if (!cell) return "N/A"
    const clone = cell.cloneNode(true) as HTMLElement
    clone.querySelectorAll(".flag-emoji").forEach((node) => node.remove())
    const text = clone.textContent?.replace(/\s+/g, " ").trim()
    return text && text.length > 0 ? text : "N/A"
  }

  const ip = getText("h3 > b")
  const reportCount = getText("p > b")
  const confidence = getText(".progress-bar > span")

  const rows = container.querySelectorAll("table tr")
  const tableInfo: Record<string, string> = {}

  rows.forEach((row) => {
    const header = row.querySelector("th")?.textContent?.trim()
    const value = getCellText(row.querySelector("td"))
    if (header && value) {
      tableInfo[header] = value
    }
  })

  const field = (key: string, fallback = "N/A") => tableInfo[key] || fallback

  const isp = field("ISP")
  const usage = field("Usage Type")
  const asn = field("ASN")
  const hostnames = field("Hostname(s)")
  const domain = field("Domain Name")
  const country = field("Country")
  const city = field("City")

  let extraText = container.querySelector("div[style*='display: flex'] p")?.textContent ?? ""
  extraText = extraText.replace(/\s+/g, " ").trim()

  return `
IP Information (AbuseIPDB):
${extraText ? `${extraText}\n\n` : ""}IP:               ${ip}
Reports:          ${reportCount}
Abuse Confidence: ${confidence}
ISP:              ${isp}
Usage:            ${usage}
ASN:              ${asn}
Hostnames:        ${hostnames}
Domain:           ${domain}
Country:          ${country}
City:             ${city}`.trim()
}

// Create the custom-styled copy button (no Bootstrap)
function createCopyButton() {
  const container = document.querySelector(".col-md-6 .well")
  if (!container || document.getElementById("IOCAbuseButton")) return

  const button = document.createElement("button")
  button.id = "IOCAbuseButton"
  button.textContent = "📋 Copy AbuseIPDB Info"

  // Scoped button styling using the custom CSS defined above
  button.classList.add("socx-extension-container")

  button.addEventListener("click", () => {
    const info = extractAndFormatInfo()
    if (info) {
      navigator.clipboard
        .writeText(info)
        .then(() => showToast("✔️ Copied to clipboard"))
        .catch((err) => {
          console.error("Clipboard error:", err)
          showToast("❌ Failed to copy", "danger")
        })
    } else {
      showToast("❌ No information found", "warning")
    }
  })

  // Wrap the button in a container with the `.socx-extension-container` class
  const extensionContainer = document.createElement("div")
  button.classList.add("socx-button")
  extensionContainer.classList.add("socx-extension-container")
  extensionContainer.appendChild(button)
  container.appendChild(extensionContainer)
}

// Wait for content to dynamically load
function waitForContent() {
  const maxAttempts = 20
  let attempts = 0

  const interval = setInterval(() => {
    const container = document.querySelector(".col-md-6 .well")
    if (container) {
      clearInterval(interval)
      createCopyButton()
    } else if (++attempts >= maxAttempts) {
      clearInterval(interval)
    }
  }, 500)
}

waitForContent()
