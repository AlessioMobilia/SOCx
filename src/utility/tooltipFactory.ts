import tippy from "tippy.js"
import { Storage } from "@plasmohq/storage"

const storage = new Storage({ area: "local" })

// ---------------- Utils ----------------
const escapeRegExp = (value: string) =>
  value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")

const normalizeAcronyms = (s: string) =>
  s
    .replace(/\bVpn\b/gi, "VPN")
    .replace(/\bTor\b/gi, "TOR")
    .replace(/\bUrl\b/gi, "URL")
    .replace(/\bIp\b/gi, "IP")

// ---------------- Costanti ----------------
const CRITICAL_KEYS = [
  "vpn",
  "proxy",
  "hosting",
  "anonymous",
  "anonymity",
  "popularity"
]

const BADGE_BASE_STYLE =
  "font-weight:600;padding:6px 12px;border-radius:4px;text-align:center;font-size:14px;margin-bottom:8px;display:block;width:fit-content;margin-left:auto;margin-right:auto;"
const BADGE_COLORS = {
  malicious: "background-color:#d32f2f;color:#fff;",
  suspicious: "background-color:#fbc02d;color:#000;",
  benign: "background-color:#66bb6a;color:#000;",
  unknown: "background-color:#9e9e9e;color:#fff;"
}


// Evidenziazione con sfondo (highlight)
const HIGHLIGHT_STYLES = {
  malicious:
    "background:#ffd7d7;color:#8b0000;font-weight:bold;padding:0 3px;border-radius:3px;",
  suspicious:
    "background:#fff3cd;color:#7a5a00;font-weight:bold;padding:0 3px;border-radius:3px;",
  benign:
    "background:#e6f4ea;color:#0b6b2f;font-weight:bold;padding:0 3px;border-radius:3px;",
  intel:
    //"background:#ede7f6;color:#4a148c;font-weight:600;padding:0 3px;border-radius:3px;",
    "font-weight:600;padding:0 3px;border-radius:3px;",
  criticalIntel:
    "background:#ffebee;color:#b71c1c;font-weight:bold;padding:0 3px;border-radius:3px;"
}

const BASE_CONTAINER_STYLE =
  "font-family:'Courier New',monospace;font-size:13px;line-height:1.4;word-break:break-word;white-space:normal;min-width:min(300px,40vw);max-width:min(500px,80vw);padding:10px;border-radius:20px;border:3px solid #333;border-radius:20px;box-shadow:4 8 10px rgba(0,0,0,0.2);"


const getIsDarkMode = async (): Promise<boolean> => {
  if (typeof chrome !== "undefined" && chrome.storage?.local) {
    try {
      const result = await new Promise<{ isDarkMode?: boolean }>((resolve) =>
        chrome.storage.local.get(["isDarkMode"], (items) => resolve(items))
      )
      if (typeof result?.isDarkMode === "boolean") {
        return result.isDarkMode
      }
    } catch {
      // fall back to storage helper
    }
  }
  const stored = await storage.get<boolean>("isDarkMode")
  return typeof stored === "boolean" ? stored : true
}

// Regex robusta per "KEY: VALUE", mantenendo il trattino
const buildKeyValueRegex = (key: string) =>
  new RegExp(
    // gruppo1 = prefisso (inizio riga o spazio, include eventuale '- '), gruppo2 = chiave, gruppo3 = valore
    String.raw`(^|[\s>])(-\s*)?(${escapeRegExp(key)})\s*:\s*([^\n<]+)`,
    "gmi"
  )

// ---------------- Tooltip ----------------
export const createTooltip = async (
  text: string,
  button: HTMLButtonElement,
  highlightTerms: string[] = []
) => {
  // Normalizza acronimi per la visualizzazione
  const normalizedForView = normalizeAcronyms(text)

  // Calcolo threat status (deterministico)
  let threatStatus: "malicious" | "suspicious" | "benign" | "unknown" = "unknown"
  {
    const abuseMatch = text.match(/Abuse\s*Score:\s*(\d+)\s*%/i)
    if (abuseMatch) {
      const score = parseInt(abuseMatch[1], 10)
      threatStatus = score === 0 ? "benign" : "malicious"
    }
    const malMatch = text.match(/Malicious:\s*(\d+)/i)
    if (malMatch) {
      const detections = parseInt(malMatch[1], 10)
      threatStatus =
        detections > 5 ? "malicious" : detections > 0 ? "suspicious" : "benign"
    }
  }

  // Chiavi da evidenziare
  const extraKeys = highlightTerms
    .map((raw) => raw.split(":")[0].trim().toLowerCase())
    .filter(Boolean)

  const keysToHighlight = Array.from(new Set([...CRITICAL_KEYS, ...extraKeys]))

  // Applica evidenziazioni (sfondo colorato)
  let html = normalizedForView
  for (const keyLower of keysToHighlight) {
    const rx = buildKeyValueRegex(keyLower)
  html = html.replace(rx, (_m, p1, bullet, k, v) => {
    const isCritical = CRITICAL_KEYS.includes(keyLower)
    if (isCritical) {
      const style = HIGHLIGHT_STYLES.criticalIntel
      const prettyKey = normalizeAcronyms(k)
      const safeBullet = bullet ?? "" // mantieni il trattino originale
      return `${p1}${safeBullet}<span style="${style}">${prettyKey}: ${v.trim()}</span>`  
    }
    return _m
  })
  }

  // Evidenziazioni speciali (Abuse Score / Malicious)
  html = html.replace(/Abuse\s*Score:\s*(\d+)\%/gi, (match, val) => {
    const score = parseInt(val, 10)
    const style =
      score === 0 ? HIGHLIGHT_STYLES.benign : HIGHLIGHT_STYLES.malicious
    return `<span style="${style}">${match}</span>`
  })

  // Evidenzia Whitelisted yes/no
  html = html.replace(/Whitelisted:\s*(yes|no)/gi, (match, val) => {
    const isYes = val.toLowerCase() === 'yes'
    if (isYes) {
      const style = HIGHLIGHT_STYLES.benign
      return `<span style="${style}">${match}</span>`
    }
    return match // se è "no", non cambia nulla
  })

  html = html.replace(/Tor:\s*(yes|no)/gi, (match, val) => {
    const isYes = val.toLowerCase() === 'yes'
    if (isYes) {
      const style = HIGHLIGHT_STYLES.malicious
      return `<span style="${style}">${match}</span>`
    }
    return match // se è "no", non cambia nulla
  })


  html = html.replace(/Malicious:\s*(\d+)/gi, (match, val) => {
    const n = parseInt(val, 10)
    const style =
      n > 5
        ? HIGHLIGHT_STYLES.malicious
        : n > 0
        ? HIGHLIGHT_STYLES.suspicious
        : HIGHLIGHT_STYLES.benign
    return `<span style="${style}">${match}</span>`
  })

  // Rispetta newline
  html = html.replaceAll("\n", "<br>")

  // Badge semplice
  const statusBadge =
    {
      malicious: `<div style="${BADGE_BASE_STYLE}${BADGE_COLORS.malicious}">⚠️ Malicious IOC</div>`,
      benign: `<div style="${BADGE_BASE_STYLE}${BADGE_COLORS.benign}">✅ Non-malicious IOC</div>`,
      suspicious: `<div style="${BADGE_BASE_STYLE}${BADGE_COLORS.suspicious}">❓ Suspicious IOC</div>`,
      unknown: `<div style="${BADGE_BASE_STYLE}${BADGE_COLORS.unknown}">ℹ️ Unknown Status</div>`
    }[threatStatus] ?? ""

  const isDarkMode = await getIsDarkMode()
const containerThemeStyle = isDarkMode
  ? `${BASE_CONTAINER_STYLE}background-color:#212529;color:#e2e8f0;`
  : `${BASE_CONTAINER_STYLE}background-color:#e2e8f0;color:#212529;`

  const contentHTML = `
    <div style="margin-top:16px;width:100%;">
      <div style="${containerThemeStyle}">
        ${statusBadge}
        <div>${html}</div>
      </div>
    </div>
  `

  const popperBg = "rgba(255, 255, 255, 0)";
  const popperColor = "rgba(255, 255, 255, 0)";

  tippy(button, {
    allowHTML: true,
    content: contentHTML,
    maxWidth: 420,
    interactive: true,
    placement: "right",
    animation: false,
    onShow(instance) {
      const box = instance.popper?.firstElementChild as HTMLElement | null
      if (box) {
        box.style.setProperty("background-color", popperBg, "important")
        box.style.setProperty("color", popperColor, "important")
        box.style.setProperty("border", "none", "important")
        box.style.boxShadow = "none"
        const content = box.querySelector(".tippy-content") as HTMLElement | null
        if (content) {
          content.style.setProperty("background-color", popperBg, "important")
          content.style.setProperty("color", popperColor, "important")
        }
      }
    }
  }).show()
}
