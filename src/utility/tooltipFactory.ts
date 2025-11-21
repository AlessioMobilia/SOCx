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
  "font-family:'Inter',sans-serif;font-weight:600;padding:4px 14px;border-radius:999px;text-align:center;font-size:12px;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:10px;display:inline-flex;justify-content:center;"
const BADGE_COLORS = {
  malicious: "background-color:#f87171;color:#2b0b0e;",
  suspicious: "background-color:#f5c242;color:#231a06;",
  benign: "background-color:#34d399;color:#032219;",
  unknown: "background-color:#475569;color:#e0e7ff;"
}


// Evidenziazione con sfondo (highlight)
const HIGHLIGHT_STYLES = {
  malicious:
    "background:rgba(248,113,113,0.2);color:#f87171;font-weight:600;padding:0 4px;border-radius:6px;",
  suspicious:
    "background:rgba(245,194,66,0.25);color:#d1900b;font-weight:600;padding:0 4px;border-radius:6px;",
  benign:
    "background:rgba(52,211,153,0.2);color:#34d399;font-weight:600;padding:0 4px;border-radius:6px;",
  intel:
    "font-weight:600;padding:0 4px;border-radius:6px;color:#f5c242;",
  criticalIntel:
    "background:rgba(255,99,132,0.2);color:#ff6b81;font-weight:700;padding:0 4px;border-radius:6px;"
}

const BASE_CONTAINER_STYLE =
  "font-family:'Inter',sans-serif;font-size:13px;line-height:1.5;word-break:break-word;white-space:normal;min-width:min(320px,42vw);max-width:min(520px,80vw);padding:18px;border-radius:18px;border:1px solid rgba(255,255,255,0.08);box-shadow:0 25px 80px rgba(5,9,18,0.6);backdrop-filter:blur(16px);"


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
  highlightTerms: string[] = [],
  iocType?: string
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
  ? `${BASE_CONTAINER_STYLE}background-color:rgba(12,20,36,0.92);color:#f4f7ff;border-color:#1f273a;`
  : `${BASE_CONTAINER_STYLE}background-color:rgba(255,255,255,0.94);color:#0b1220;border-color:#e2e8f0;`

  const headerTone = isDarkMode ? "rgba(244,247,255,0.65)" : "rgba(17,19,34,0.55)"
  const liveTone = isDarkMode ? "#ffd24d" : "#b7791f"

  const headerLabel = (iocType ?? "IOC").toUpperCase()
  const headerStrip = `
    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:6px;">
      <span style="font-size:11px;letter-spacing:0.3em;text-transform:uppercase;color:${headerTone};">SOCx Intel</span>
      <span style="font-size:11px;letter-spacing:0.2em;text-transform:uppercase;color:${liveTone};">${headerLabel}</span>
    </div>
    <div style="height:1px;background:rgba(255,255,255,0.08);margin-bottom:12px;"></div>
  `

  const contentHTML = `
    <div style="margin-top:12px;width:100%;position:relative;z-index:2147483650;">
      <div style="${containerThemeStyle}">
        ${headerStrip}
        ${statusBadge}
        <div style="margin-top:8px;">${html}</div>
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
    zIndex: 2147483650,
    placement: "right",
    animation: false,
    onShow(instance) {
      if (instance.popper) {
        instance.popper.style.setProperty("z-index", "2147483650", "important")
      }
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
