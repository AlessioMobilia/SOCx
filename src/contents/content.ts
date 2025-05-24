import type { PlasmoCSConfig } from "plasmo"
import { sendToBackground } from "@plasmohq/messaging"
import {
  extractIOCs,
  identifyIOC,
  showNotification,
  saveIOC,
  formatVirusTotalData,
  formatAbuseIPDBData,
  formatSelectedText
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

  // inizializzazione sicura
  if (!(window as any)._formatScriptInitialized) {
    ;(window as any)._formatScriptInitialized = true





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
      return sendToBackground({
        name: "check-bulk-iocs",
        body: {
          iocList: [ioc],
          services: selectedServices
        }
      })
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
      let timeout: NodeJS.Timeout
      return (...args: any[]) => {
        clearTimeout(timeout)
        timeout = setTimeout(() => fn(...args), delay)
      }
    }



    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message?.name === "copy-to-clipboard") {
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
