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

async function handleSelection() {
  const selection = window.getSelection()
  const selectedText = selection?.toString().trim()
  if (!selectedText || (selectedText === oldSelection && currentButton)) return

  // Limit to max 2 distinct words
  const uniqueWords = Array.from(
    new Set(selectedText.split(/\s+/).filter((w) => w.length > 0))
  )
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

  const range = selection!.getRangeAt(0)
  let rect = range.getBoundingClientRect()

  // If selected inside input/textarea
  if (rect.width === 0 && rect.height === 0) {
    const activeElement = document.activeElement as HTMLElement
    if (activeElement instanceof HTMLInputElement || activeElement instanceof HTMLTextAreaElement) {
      const input = activeElement
      const computedStyle = window.getComputedStyle(input)

      const mirrorDiv = document.createElement("div")
      mirrorDiv.style.position = "absolute"
      mirrorDiv.style.visibility = "hidden"
      mirrorDiv.style.whiteSpace = "pre-wrap"
      mirrorDiv.style.wordWrap = "break-word"
      mirrorDiv.style.left = "-9999px"

      for (const prop of computedStyle) {
        mirrorDiv.style.setProperty(prop, computedStyle.getPropertyValue(prop))
      }

      mirrorDiv.textContent = input.value.substring(0, input.selectionEnd || 0)

      const span = document.createElement("span")
      mirrorDiv.appendChild(span)
      document.body.appendChild(mirrorDiv)

      const spanRect = span.getBoundingClientRect()
      const inputRect = input.getBoundingClientRect()

      rect = {
        top: inputRect.top + (spanRect.top - mirrorDiv.getBoundingClientRect().top) - input.scrollTop,
        left: inputRect.left + (spanRect.left - mirrorDiv.getBoundingClientRect().left) - input.scrollLeft,
        width: spanRect.width,
        height: spanRect.height,
        right: inputRect.left + (spanRect.left - mirrorDiv.getBoundingClientRect().left) + spanRect.width - input.scrollLeft,
        bottom: inputRect.top + (spanRect.top - mirrorDiv.getBoundingClientRect().top) + spanRect.height - input.scrollTop,
        toJSON: () => rect
      } as DOMRect

      document.body.removeChild(mirrorDiv)
    }
  }

  if (rect.width === 0 && rect.height === 0) return

  // Create VT/AbuseIPDB button if supported
  if (isSupported) {
    const button = createButton(ioc, async () => {
      try {
        const response = await getIOCInfo(ioc)
        console.log("IOC data:", response)
        const data = response.results?.[Object.keys(response.results)[0]]

        let info = ""

        if (type === "IP") {
          const abuseInfo = formatAbuseIPDBData(data?.AbuseIPDB)
          info = abuseInfo?.trim() ? abuseInfo : "⚠️ No data available from AbuseIPDB for this IP."
        } else {
          const vtInfo = formatVirusTotalData(data?.VirusTotal)
          info = vtInfo?.trim() ? vtInfo : "⚠️ No information available from VirusTotal for this IOC."
        }

        createTooltip(info, button)
        navigator.clipboard.writeText(info)

        if (!(await saveIOC(type, ioc))) {
          showNotification("Error", "Failed to save the IOC.")
        }
      } catch (err) {
        console.error("Error fetching IOC data:", err)
        createTooltip("❌ Error retrieving IOC information.", button)
      }
    })

    if (button) {
      document.body.appendChild(button)
      button.style.position = "fixed"
      currentButton = button
    }
  }

  // Always create magic button
  const magicButton = createMagicButton(ioc, () => {
    requestIOCInfo(ioc)
  })

  if (magicButton) {
    document.body.appendChild(magicButton)
    magicButton.style.position = "fixed"
    currentMagicButton = magicButton
  }

  repositionButtons()
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
