import type { PlasmoCSConfig } from "plasmo"
import { showBootstrapToast } from "../utility/utils"

export const config: PlasmoCSConfig = {
  matches: ["https://www.abuseipdb.com/check/*"],
  all_frames: true
}

// Extract and format information from the page
function extractAndFormatInfo(): string | null {
  const container = document.querySelector(".col-md-6 .well");
  if (!container) return null;

  const getText = (selector: string): string =>
    container.querySelector(selector)?.textContent?.trim() || "N/A";

  const ip = getText("h3 > b");
  const reportCount = getText("p > b");
  const confidence = getText(".progress-bar > span");

  const rows = container.querySelectorAll("table tr");
  const tableInfo: Record<string, string> = {};

  rows.forEach((row) => {
    const th = row.querySelector("th")?.textContent?.trim();
    const td = row.querySelector("td")?.textContent?.trim();
    if (th && td) tableInfo[th] = td;
  });

  const isp = tableInfo["ISP"] || "N/A";
  const usage = tableInfo["Usage Type"] || "N/A";
  const asn = tableInfo["ASN"] || "N/A";
  const hostname = tableInfo["Hostname(s)"] || "N/A";
  const domain = tableInfo["Domain Name"] || "N/A";
  const country = tableInfo["Country"] || "N/A";
  const city = tableInfo["City"] || "N/A";

  let extraText = container.querySelector("div[style*='display: flex'] p")?.textContent?.trim() ?? "";
  extraText = extraText.replace(/\s+/g, " ").trim(); // clean up extra whitespace and newlines

  return `
IP Information (AbuseIPDB):
${extraText ? `${extraText}\n\n` : ""}IP:               ${ip}
Reports:          ${reportCount}
Abuse Confidence: ${confidence}
ISP:              ${isp}
Usage:            ${usage}
ASN:              ${asn}
Hostnames:        ${hostname}
Domain:           ${domain}
Country:          ${country}
City:             ${city}`.trim();
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
        .then(() => showBootstrapToast("✔️ Copied to clipboard"))
        .catch((err) => {
          console.error("Clipboard error:", err)
          showBootstrapToast("❌ Failed to copy", "danger")
        })
    } else {
      showBootstrapToast("❌ No information found", "warning")
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
