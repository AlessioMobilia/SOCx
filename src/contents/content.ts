import type { PlasmoCSConfig } from "plasmo"
import { sendToBackground } from "@plasmohq/messaging"
import {
  extractIOCs,
  identifyIOC,
  showNotification,
  saveIOC,
  formatVirusTotalData,
  formatAbuseIPDBData,
  collectIpIntelSignals,
  formatSelectedText
} from "../utility/utils"
import { servicesConfig } from "../utility/servicesConfig"
import { createButton, createMagicButton } from "../utility/buttonFactory"
import { createTooltip } from "../utility/tooltipFactory"
import "tippy.js/dist/tippy.css"
import { Storage } from "@plasmohq/storage"

console.log("[Plasmo] Content script loaded");
const storage = new Storage({ area: "local" })

export const config: PlasmoCSConfig = {
  matches: ["<all_urls>"],
  all_frames: true
}

const MAX_SELECTION_LENGTH = 256
const MAX_UNIQUE_WORDS = 2

  // inizializzazione sicura
  if (!(window as any)._formatScriptInitialized) {
    ;(window as any)._formatScriptInitialized = true
    // Controlla se siamo nell'iframe o nella finestra principale
    const isInIframe = window.self !== window.top;





    let currentButton: HTMLButtonElement | null = null
    let currentMagicButton: HTMLButtonElement | null = null
    let lastSelectionSignature: string | null = null
    let repositionScheduled = false

    document.addEventListener("mouseup", debounce(handleSelection, 300))
    document.addEventListener("selectionchange", handleSelectionChange)

    const clearSelectionUI = () => {
      if (!currentButton && !currentMagicButton && !lastSelectionSignature) {
        return
      }

      currentButton?.remove()
      currentMagicButton?.remove()
      currentButton = currentMagicButton = null
      lastSelectionSignature = null
    }

    function handleSelectionChange() {
      const selection = window.getSelection()
      if (!selection || selection.rangeCount === 0 || selection.isCollapsed) {
        clearSelectionUI()
      }
    }

    // Helper: Estimate caret position for input/textarea
    // Helper: Estimate caret position for input/textarea
    function estimateCaretRect(inputEl: Element | null): DOMRect | null {
      if (!inputEl) return null
      if (inputEl instanceof HTMLElement && inputEl.isContentEditable) {
        const selection = inputEl.ownerDocument.getSelection()
        if (selection && selection.rangeCount > 0) {
          const range = selection.getRangeAt(0).cloneRange()
          range.collapse(false)
          const rects = range.getClientRects()
          if (rects.length > 0) {
            return rects[rects.length - 1]
          }
          const fallbackRect = range.getBoundingClientRect()
          if (fallbackRect.width || fallbackRect.height) {
            return fallbackRect
          }
        }
        return inputEl.getBoundingClientRect()
      }

      if (
        !(inputEl instanceof HTMLInputElement) &&
        !(inputEl instanceof HTMLTextAreaElement)
      ) {
        return inputEl.getBoundingClientRect()
      }

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

    const buildSelectionSignature = (
      text: string,
      rect: DOMRect | null
    ): string => {
      if (!rect) return `${text}-no-rect-${window.location.href}`
      return `${text}-${Math.round(rect.top)}-${Math.round(rect.left)}-${window.location.href}`
    }

    const getSelectionRect = (selection: Selection | null): DOMRect | null => {
      if (!selection) return null
      if (selection.rangeCount > 0) {
        const rangeRect = selection.getRangeAt(0).getBoundingClientRect()
        if (rangeRect.width || rangeRect.height) {
          return rangeRect
        }
      }

      const activeEl = document.activeElement
      if (
        activeEl instanceof HTMLInputElement ||
        activeEl instanceof HTMLTextAreaElement ||
        (activeEl instanceof HTMLElement && activeEl.isContentEditable)
      ) {
        return estimateCaretRect(activeEl)
      }

      return activeEl?.getBoundingClientRect() ?? null
    }

    async function handleSelection() {
      const selection = window.getSelection()
      const selectedText = selection?.toString().trim() ?? ""
      if (!selectedText) {
        clearSelectionUI()
        return
      }

      if (selectedText.length > MAX_SELECTION_LENGTH) {
        clearSelectionUI()
        return
      }

      const uniqueWords = new Set(selectedText.split(/\s+/).filter(Boolean))
      if (uniqueWords.size > MAX_UNIQUE_WORDS) {
        clearSelectionUI()
        return
      }

      const iocs = extractIOCs(selectedText)
      if (!iocs || iocs.length !== 1) {
        clearSelectionUI()
        return
      }

      const ioc = iocs[0]
      const type = identifyIOC(ioc)
      if (!type) {
        clearSelectionUI()
        return
      }

      const vtSupported = ["IP", "Domain", "URL", "Hash"]
      const abuseSupported = ["IP"]
      const isSupported = vtSupported.includes(type) || abuseSupported.includes(type)
      if (!isSupported) {
        clearSelectionUI()
        return
      }

      let rect: DOMRect | null = null
      try {
        rect = getSelectionRect(selection ?? null)
      } catch (err) {
        console.warn("Unable to derive selection rect:", err)
        rect = null
      }

      const selectionSignature = buildSelectionSignature(selectedText, rect)
      if (selectionSignature === lastSelectionSignature && currentButton) {
        return
      }
      lastSelectionSignature = selectionSignature

      currentButton?.remove()
      currentMagicButton?.remove()

      if (!rect || (!rect.width && !rect.height && rect.top <= 0 && rect.left <= 0)) {
        const fallback = document.activeElement?.getBoundingClientRect()
        if (!fallback) {
          clearSelectionUI()
          return
        }
        rect = fallback
      }

      const button = isSupported ? createButton(ioc, async () => {
        try {
          const response = await getIOCInfo(ioc)
          const data = response.results?.[Object.keys(response.results)[0]]
          const ipSignals = collectIpIntelSignals(data?.Ipapi, data?.ProxyCheck)
          const baseInfo = type === "IP"
            ? formatAbuseIPDBData(data?.AbuseIPDB, ipSignals) || "⚠️ No data from AbuseIPDB"
            : formatVirusTotalData(data?.VirusTotal) || "⚠️ No data from VirusTotal"
          const tooltipInfo =
            type === "IP" && ipSignals.length > 0
              ? `${baseInfo}\nEnriched Signals: ${ipSignals.join(", ")}`
              : baseInfo

          await createTooltip(baseInfo, button, ipSignals)
          navigator.clipboard.writeText(baseInfo)
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




    const scheduleReposition = () => {
      if (repositionScheduled) return
      repositionScheduled = true

      const run = () => {
        repositionScheduled = false
        repositionButtons()
      }

      if (typeof window.requestAnimationFrame === "function") {
        window.requestAnimationFrame(run)
      } else {
        window.setTimeout(run, 16)
      }
    }

    // Update button positions on scroll and resize without spamming layout thrashing
    window.addEventListener("scroll", scheduleReposition, { passive: true })
    window.addEventListener("resize", scheduleReposition)

    function repositionButtons() {
      const selection = window.getSelection?.()
      if (!selection) return
      let rect: DOMRect | null = null
      try {
        rect = getSelectionRect(selection)
      } catch (err) {
        rect = null
      }
      if (!rect) return

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
      scheduleReposition()
    })
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      characterData: true
    })

    scheduleReposition()


    const getEnrichmentPrefs = async () => {
      try {
        const prefs = await storage.getMany([
          "ipapiEnrichmentEnabled",
          "proxyCheckEnabled"
        ])
        const ipapiSetting = prefs.ipapiEnrichmentEnabled
        const proxySetting = prefs.proxyCheckEnabled
        return {
          ipapi: Boolean(ipapiSetting),
          proxy: Boolean(proxySetting)
        }
      } catch {
        return { ipapi: false, proxy: false }
      }
    }

    function getIOCInfo(ioc: string): Promise<any> {
      const selectedServices = [identifyIOC(ioc) === "IP" ? "AbuseIPDB" : "VirusTotal"]
      console.log("Selected services:", selectedServices)
      return getEnrichmentPrefs().then((prefs) =>
        sendToBackground({
          name: "check-bulk-iocs",
          body: {
            iocList: [ioc],
            services: selectedServices,
            includeIpapi: prefs.ipapi,
            includeProxyCheck: prefs.proxy
          }
        })
      )
    }


    function requestIOCInfo(ioc: string): Promise<any> {
      console.log("Requesting IOC info for:", ioc)
      return sendToBackground({
        name: "magic-ioc-request",
        body: {
          IOC: ioc
        }
      })
    }



    function debounce(fn: Function, delay: number) {
      let timeout: ReturnType<typeof setTimeout>
      return (...args: any[]) => {
        clearTimeout(timeout)
        timeout = setTimeout(() => fn(...args), delay)
      }
    }



    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message?.name === "copy-to-clipboard") {
        console.log("Received copy-to-clipboard message:", message)
        const text = message.body?.text
        if (typeof text === "string") {
          navigator.clipboard.writeText(text)
            .then(() => {
              sendResponse({ success: true })
            })
            .catch((err) => {
              console.warn("Primary clipboard API failed, trying fallback:", err)

              // Fallback method using execCommand
              try {
                const textarea = document.createElement("textarea")
                textarea.value = text
                textarea.style.position = "fixed"
                textarea.style.top = "-1000px"
                textarea.style.opacity = "0"
                document.body.appendChild(textarea)
                textarea.focus()
                textarea.select()

                const success = document.execCommand("copy")
                document.body.removeChild(textarea)

                sendResponse({
                  success,
                  fallback: true
                })
              } catch (fallbackErr) {
                console.error("Clipboard fallback also failed:", fallbackErr)
                sendResponse({
                  success: false,
                  error: fallbackErr.message
                })
              }
            })

          return true // Keep channel open for async response
        } else {
          sendResponse({ success: false, error: "Invalid text" })
        }
      } else if (message?.name === "format-selection") {
        const formattedText = formatSelectedText(lastValidSelection);
        sendResponse({ success: true, formatted: formattedText });
        return false;
      }
    })


    let lastValidSelection = null

    document.addEventListener("selectionchange", () => {
      const sel = window.getSelection()
      if (sel && sel.rangeCount > 0 && !sel.isCollapsed) {
        lastValidSelection = sel
      }
    })

  }
