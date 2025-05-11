import type { PlasmoCSConfig } from "plasmo"
import "bootstrap/dist/css/bootstrap.min.css"
import { showBootstrapToast } from "../utility/utils"

export const config: PlasmoCSConfig = {
  matches: ["https://www.abuseipdb.com/check/*"],
  all_frames: true
}

// Estrai e formatta le informazioni
function extractAndFormatInfo(): string | null {
  const container = document.querySelector(".col-md-6 .well");
  if (!container) return null;

  const getText = (selector: string): string =>
    container.querySelector(selector)?.textContent?.trim() || "N/D";

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

  const isp = tableInfo["ISP"] || "N/D";
  const usage = tableInfo["Usage Type"] || "N/D";
  const asn = tableInfo["ASN"] || "N/D";
  const hostname = tableInfo["Hostname(s)"] || "N/D";
  const domain = tableInfo["Domain Name"] || "N/D";
  const country = tableInfo["Country"] || "N/D";
  const city = tableInfo["City"] || "N/D";

  let extraText = container.querySelector("div[style*='display: flex'] p")?.textContent?.trim() ?? "";
  extraText = extraText.replace(/\s+/g, " ").trim(); // rimuove spazi doppi e newline inutili

  return `
Informazioni IP (AbuseIPDB):
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



// Crea il pulsante con stile Bootstrap
function createCopyButton() {
  const container = document.querySelector(".col-md-6 .well")
  if (!container || document.getElementById("IOCAbuseButton")) return

  const button = document.createElement("button")
  button.id = "IOBAbuseButton"
  button.textContent = "📋 Copia informazioni AbuseIPDB"

  Object.assign(button.style, {
    marginTop: "16px",
    width: "100%",
    padding: "10px 14px",
    backgroundColor: "#0d6efd",
    color: "#fff",
    border: "1px solid rgb(51, 109, 196)",
    borderRadius: "6px",
    fontSize: "15px",
    fontWeight: "600",
    cursor: "pointer",
  })

  button.addEventListener("click", () => {
    const info = extractAndFormatInfo()
    if (info) {
      navigator.clipboard
        .writeText(info)
        .then(() => showBootstrapToast("✔️ Copied to clipboard"))
        .catch((err) => {
          console.error("Clipboard error:", err)
          showBootstrapToast("❌ Copy failed", "danger")
        })
    } else {
      showBootstrapToast("❌ No information found", "warning")
    }
  })

  container.appendChild(button)
}

// Attesa dinamica del contenuto
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
