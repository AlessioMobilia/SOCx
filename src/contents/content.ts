import type { PlasmoCSConfig } from "plasmo"
import {
  extractIOCs,
  identifyIOC,
  showNotification,
  saveIOC,
  formatVirusTotalData,
  formatAbuseIPDBData
} from "../utility/utils"
import { servicesConfig } from "../utility/servicesConfig"
import { createButton, createMagicButton } from "../utility/buttonFactory"
import { createTooltip } from "../utility/tooltipFactory"
import "tippy.js/dist/tippy.css"
import "./content.css"


export const config: PlasmoCSConfig = {
  matches: ["<all_urls>"],
  all_frames: true
}

// Clipboard fallback copy method
function copyTextWithFallback(text: string): boolean {
  try {
    const textarea = document.createElement("textarea")
    textarea.value = text
    textarea.style.position = "fixed"
    textarea.style.opacity = "0"
    textarea.style.pointerEvents = "none"

    const parent = document.body || document.documentElement || document.head
    parent.appendChild(textarea)
    textarea.focus()
    textarea.select()

    const successful = document.execCommand("copy")
    parent.removeChild(textarea)
    return successful
  } catch (err) {
    console.error("Fallback copy failed:", err)
    return false
  }
}

// Listen for clipboard copy messages
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "copyToClipboard" && typeof message.text === "string") {
    navigator.clipboard.writeText(message.text)
      .then(() => sendResponse({ success: true }))
      .catch((err) => {
        console.warn("navigator.clipboard.writeText failed, using fallback:", err.message)
        const success = copyTextWithFallback(message.text)
        if (success) {
          sendResponse({ success: true })
        } else {
          sendResponse({ error: "Copy failed with fallback as well" })
        }
      })

    return true // Indicates async response
  }
})

let currentButton: HTMLButtonElement | null = null
let currentMagicButton: HTMLButtonElement | null = null
let oldSelection: string | null = null

document.addEventListener("mouseup", debounce(handleSelection, 300))
document.addEventListener("selectionchange", handleSelectionChange)

function handleSelectionChange() {
  const selection = window.getSelection()
  if (!selection || selection.toString().trim() === "") {
    currentButton?.remove()
    currentMagicButton?.remove()
    currentButton = currentMagicButton = null
    oldSelection = null
  }
}

// Helper: Estimate caret position for input/textarea
// Helper: Estimate caret position for input/textarea
function estimateCaretRect(inputEl) {
  const mirrorDiv = document.createElement("div")
  const computedStyle = getComputedStyle(inputEl)

  for (const prop of computedStyle) {
    mirrorDiv.style.setProperty(prop, computedStyle.getPropertyValue(prop))
  }

  mirrorDiv.style.position = "absolute"
  mirrorDiv.style.visibility = "hidden"
  mirrorDiv.style.whiteSpace = "pre-wrap"
  mirrorDiv.style.wordWrap = "break-word"
  mirrorDiv.style.boxSizing = computedStyle.boxSizing
  mirrorDiv.style.padding = computedStyle.padding
  mirrorDiv.style.border = computedStyle.border
  mirrorDiv.style.left = "-9999px"

  const text = inputEl.value.substring(0, inputEl.selectionEnd || 0)
  mirrorDiv.textContent = text

  const span = document.createElement("span")
  span.textContent = "\u200b" // zero-width space
  mirrorDiv.appendChild(span)
  document.body.appendChild(mirrorDiv)

  const spanRect = span.getBoundingClientRect()
  const inputRect = inputEl.getBoundingClientRect()
  const mirrorRect = mirrorDiv.getBoundingClientRect()

  const rect = {
    top: inputRect.top + (spanRect.top - mirrorRect.top) - inputEl.scrollTop,
    left: inputRect.left + (spanRect.left - mirrorRect.left) - inputEl.scrollLeft,
    width: 0,
    height: spanRect.height || 16,
    right: inputRect.left + (spanRect.left - mirrorRect.left) - inputEl.scrollLeft,
    bottom: inputRect.top + (spanRect.top - mirrorRect.top) + (spanRect.height || 16) - inputEl.scrollTop,
    x: inputRect.left + (spanRect.left - mirrorRect.left) - inputEl.scrollLeft,
    y: inputRect.top + (spanRect.top - mirrorRect.top) - inputEl.scrollTop,
    toJSON: () => rect
  }

  document.body.removeChild(mirrorDiv)
  return rect
}

async function handleSelection() {
  const selection = window.getSelection()
  const selectedText = selection?.toString().trim()
  if (!selectedText || (selectedText === oldSelection && currentButton)) return

  const uniqueWords = Array.from(new Set(selectedText.split(/\s+/).filter(Boolean)))
  if (uniqueWords.length > 2) return

  oldSelection = selectedText
  const iocs = extractIOCs(selectedText)
  if (!iocs || iocs.length !== 1) return

  const ioc = iocs[0]
  const type = identifyIOC(ioc)
  if (!type) return

  const vtSupported = ["IP", "Domain", "URL", "Hash"]
  const abuseSupported = ["IP"]
  const isSupported = vtSupported.includes(type) || abuseSupported.includes(type)

  currentButton?.remove()
  currentMagicButton?.remove()

  let rect = selection.getRangeAt(0).getBoundingClientRect()

  if (rect.width === 0 && rect.height === 0) {
    const activeEl = document.activeElement
    if (
      activeEl instanceof HTMLInputElement ||
      activeEl instanceof HTMLTextAreaElement ||
      (activeEl instanceof HTMLElement && activeEl.isContentEditable)
    ) {
      rect = estimateCaretRect(activeEl)
    }
  }

  // Fallback se rect non valido
  if (!rect || rect.top <= 0 || rect.left <= 0) {
    const fallback = document.activeElement?.getBoundingClientRect()
    if (!fallback || fallback.top <= 0 || fallback.left <= 0) return
    rect = fallback
  }

  const button = isSupported ? createButton(ioc, async () => {
    try {
      const response = await getIOCInfo(ioc)
      const data = response.results?.[Object.keys(response.results)[0]]
      const info = type === "IP"
        ? formatAbuseIPDBData(data?.AbuseIPDB) || "⚠️ No data from AbuseIPDB"
        : formatVirusTotalData(data?.VirusTotal) || "⚠️ No data from VirusTotal"

      await createTooltip(info, button)
      navigator.clipboard.writeText(info)
      if (!(await saveIOC(type, ioc))) {
        showNotification("Error", "Failed to save the IOC")
      }
    } catch (err) {
      console.error("Fetch error:", err)
      await createTooltip("❌ Error retrieving IOC information.", button)
    }
  }) : null

  if (button) {
    document.body.appendChild(button)
    button.style.position = "fixed"
    button.style.left = `${rect.right + 5}px`
    button.style.top = `${rect.top}px`
    currentButton = button
  }

  const magicButton = createMagicButton(ioc, () => requestIOCInfo(ioc))
  if (magicButton) {
    document.body.appendChild(magicButton)
    magicButton.style.position = "fixed"
    magicButton.style.left = `${rect.right + (button?.offsetWidth || 30) + 10}px`
    magicButton.style.top = `${rect.top}px`
    currentMagicButton = magicButton
  }
}




// Update button positions on scroll and resize
window.addEventListener("scroll", repositionButtons)
window.addEventListener("resize", repositionButtons)

function repositionButtons() {
  const selection = window.getSelection?.()
  if (!selection || selection.rangeCount === 0) return

  const range = selection.getRangeAt(0)
  const rect = range.getBoundingClientRect()

  if (currentButton) {
    currentButton.style.left = `${rect.right + 3}px`
    currentButton.style.top = `${rect.top}px`
  }

  if (currentMagicButton) {
    const offset = currentButton ? currentButton.clientWidth + 10 : 10
    currentMagicButton.style.left = `${rect.right + offset}px`
    currentMagicButton.style.top = `${rect.top}px`
  }
}

// Observe DOM changes to adjust button positions
const observer = new MutationObserver(() => {
  repositionButtons()
})
observer.observe(document.body, {
  childList: true,
  subtree: true,
  attributes: true,
  characterData: true
})

setTimeout(() => repositionButtons(), 0)

function getIOCInfo(ioc: string): Promise<any> {
  const selectedServices = [identifyIOC(ioc) === "IP" ? "AbuseIPDB" : "VirusTotal"]
  console.log("Selected services:", selectedServices)
  console.log("IOC:", ioc)
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(
      { action: "checkBulkIOCs", iocList: [ioc], services: selectedServices },
      resolve
    )
  })
}

function requestIOCInfo(ioc: string): Promise<any> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ action: "MagicIOCRequest", IOC: ioc }, resolve)
  })
}

function debounce(fn: Function, delay: number) {
  let timeout: NodeJS.Timeout
  return (...args: any[]) => {
    clearTimeout(timeout)
    timeout = setTimeout(() => fn(...args), delay)
  }
}
