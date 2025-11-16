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
import { estimateCaretRect } from "../utility/caret"
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
const BUTTON_OFFSET = 6
const BUTTON_MARGIN = 8
const MAGIC_BUTTON_GAP = 10
const availableServices = servicesConfig.availableServices as Record<string, string[]>

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

    const clampValue = (value: number, min: number, max: number) =>
      Math.min(Math.max(value, min), max)

    const getDeepActiveElement = (): Element | null => {
      let active: Element | null = document.activeElement
      while (active instanceof HTMLElement && active.shadowRoot?.activeElement) {
        active = active.shadowRoot.activeElement
      }
      return active
    }

    const placeFixedButton = (
      button: HTMLButtonElement,
      targetLeft: number,
      targetTop: number,
      selectionRect?: DOMRect
    ) => {
      const docEl = document.documentElement
      const viewportWidth = docEl.clientWidth
      const viewportHeight = docEl.clientHeight
      const width = button.offsetWidth || 28
      const height = button.offsetHeight || 28
      let clampedLeft = clampValue(
        targetLeft,
        BUTTON_MARGIN,
        Math.max(BUTTON_MARGIN, viewportWidth - width - BUTTON_MARGIN)
      )
      let clampedTop = clampValue(
        targetTop,
        BUTTON_MARGIN,
        Math.max(BUTTON_MARGIN, viewportHeight - height - BUTTON_MARGIN)
      )
      if (selectionRect) {
        const overlapsHorizontally =
          clampedLeft < selectionRect.right && clampedLeft + width > selectionRect.left

        if (overlapsHorizontally) {
          const rightCandidate = selectionRect.right + BUTTON_OFFSET
          const leftCandidate = selectionRect.left - BUTTON_OFFSET - width
          const canPlaceRight = rightCandidate + width <= viewportWidth - BUTTON_MARGIN
          const canPlaceLeft = leftCandidate >= BUTTON_MARGIN

          if (canPlaceRight || canPlaceLeft) {
            clampedLeft = clampValue(
              canPlaceRight ? rightCandidate : leftCandidate,
              BUTTON_MARGIN,
              Math.max(BUTTON_MARGIN, viewportWidth - width - BUTTON_MARGIN)
            )
          } else {
            const aboveCandidate = selectionRect.top - BUTTON_OFFSET - height
            const belowCandidate = selectionRect.bottom + BUTTON_OFFSET
            const canPlaceAbove = aboveCandidate >= BUTTON_MARGIN
            const canPlaceBelow =
              belowCandidate + height <= viewportHeight - BUTTON_MARGIN

            if (canPlaceAbove || canPlaceBelow) {
              clampedTop = clampValue(
                canPlaceAbove ? aboveCandidate : belowCandidate,
                BUTTON_MARGIN,
                Math.max(BUTTON_MARGIN, viewportHeight - height - BUTTON_MARGIN)
              )
            }
          }
        }
      }

      button.style.position = "fixed"
      button.style.left = `${clampedLeft}px`
      button.style.top = `${clampedTop}px`
      return { left: clampedLeft, top: clampedTop, width, height }
    }

    const getSingleButtonLeft = (rect: DOMRect, width: number): number => {
      const docEl = document.documentElement
      const availableRight = docEl.clientWidth - rect.right - BUTTON_MARGIN
      const availableLeft = rect.left - BUTTON_MARGIN
      const placeRight =
        availableRight >= width + BUTTON_OFFSET || availableRight >= availableLeft
      return placeRight
        ? rect.right + BUTTON_OFFSET
        : rect.left - BUTTON_OFFSET - width
    }

    const getVerticalAnchor = (rect: DOMRect, button: HTMLButtonElement | null) => {
      const height = button?.offsetHeight || 28
      return rect.top + (rect.height - height) / 2
    }

    function positionButtonGroup(geometry: SelectionGeometry) {
      const anchorRect = geometry.caret ?? geometry.bounds
      const selectionRect = geometry.bounds ?? geometry.caret
      if (!anchorRect || !selectionRect) {
        return
      }

      if (currentButton && currentMagicButton) {
        const primaryWidth = currentButton.offsetWidth || 28
        const magicWidth = currentMagicButton.offsetWidth || 28
        const primaryTop = getVerticalAnchor(anchorRect, currentButton)
        const magicTop = getVerticalAnchor(anchorRect, currentMagicButton)
        const docEl = document.documentElement
        const totalWidth = primaryWidth + MAGIC_BUTTON_GAP + magicWidth
        const availableRight = docEl.clientWidth - selectionRect.right - BUTTON_MARGIN
        const availableLeft = selectionRect.left - BUTTON_MARGIN
        const placeRight =
          availableRight >= totalWidth + BUTTON_OFFSET || availableRight >= availableLeft

        if (placeRight) {
          const primaryPlacement = placeFixedButton(
            currentButton,
            selectionRect.right + BUTTON_OFFSET,
            primaryTop,
            selectionRect
          )
          placeFixedButton(
            currentMagicButton,
            primaryPlacement.left + primaryPlacement.width + MAGIC_BUTTON_GAP,
            magicTop,
            selectionRect
          )
        } else {
          const primaryPlacement = placeFixedButton(
            currentButton,
            selectionRect.left - BUTTON_OFFSET - primaryWidth,
            primaryTop,
            selectionRect
          )
          placeFixedButton(
            currentMagicButton,
            primaryPlacement.left - magicWidth - MAGIC_BUTTON_GAP,
            magicTop,
            selectionRect
          )
        }
        return
      }

      if (currentButton) {
        placeFixedButton(
          currentButton,
          getSingleButtonLeft(selectionRect, currentButton.offsetWidth || 28),
          getVerticalAnchor(anchorRect, currentButton),
          selectionRect
        )
      }

      if (currentMagicButton) {
        placeFixedButton(
          currentMagicButton,
          getSingleButtonLeft(selectionRect, currentMagicButton.offsetWidth || 28),
          getVerticalAnchor(anchorRect, currentMagicButton),
          selectionRect
        )
      }
    }

    type SelectionGeometry = {
      caret: DOMRect | null
      bounds: DOMRect | null
    }

    const buildSelectionSignature = (
      text: string,
      geometry: SelectionGeometry | null
    ): string => {
      const rect = geometry?.bounds ?? geometry?.caret
      if (!rect) return `${text}-no-rect-${window.location.href}`
      return `${text}-${Math.round(rect.top)}-${Math.round(rect.left)}-${window.location.href}`
    }

    const getFocusRect = (selection: Selection): DOMRect | null => {
      const focusNode = selection.focusNode
      if (!focusNode) {
        return null
      }

      try {
        const focusRange = document.createRange()
        focusRange.setStart(focusNode, selection.focusOffset)
        focusRange.collapse(true)
        const focusRects = focusRange.getClientRects()
        if (focusRects.length > 0) {
          return focusRects[focusRects.length - 1]
        }
        const collapsedRect = focusRange.getBoundingClientRect()
        if (collapsedRect.width || collapsedRect.height) {
          return collapsedRect
        }
      } catch (err) {
        console.warn("Unable to compute focus rect:", err)
      }

      return null
    }

    const getSelectionGeometry = (selection: Selection | null): SelectionGeometry | null => {
      let caretRect: DOMRect | null = null
      let boundsRect: DOMRect | null = null
      const activeEl = getDeepActiveElement()
      if (activeEl instanceof HTMLInputElement || activeEl instanceof HTMLTextAreaElement) {
        const caretEstimate = estimateCaretRect(activeEl) ?? activeEl.getBoundingClientRect()
        caretRect = caretEstimate
        boundsRect = caretEstimate
        return { caret: caretRect, bounds: boundsRect }
      }

      if (activeEl instanceof HTMLElement && activeEl.isContentEditable) {
        caretRect = estimateCaretRect(activeEl)
        boundsRect = caretRect ?? activeEl.getBoundingClientRect()
      }

      if (selection?.rangeCount) {
        if (!caretRect) {
          caretRect = getFocusRect(selection)
        }

        const range = selection.getRangeAt(0)
        const rangeRect = range.getBoundingClientRect()
        if (rangeRect.width || rangeRect.height) {
          boundsRect = rangeRect
        }
      }

      if (!caretRect && boundsRect) {
        caretRect = boundsRect
      }

      if (!caretRect && !boundsRect) {
        return null
      }

      return { caret: caretRect, bounds: boundsRect }
    }

    const sanitizeToken = (raw: string): string => raw.replace(/^\W+|\W+$/g, "")

    const extractTokenFromSelection = (sel: Selection | null): string | null => {
      if (!sel) return null
      const tryNode = (node: Node | null, offset: number): string | null => {
        if (node && node.nodeType === Node.TEXT_NODE) {
          const text = (node as Text).data || ""
          const idx = clampValue(offset, 0, text.length)
          let start = idx
          let end = idx
          const isAllowed = (ch: string) => /[A-Za-z0-9_:\.\-\/\%]/.test(ch)
          while (start > 0 && isAllowed(text[start - 1])) start--
          while (end < text.length && isAllowed(text[end])) end++
          const token = text.slice(start, end)
          return token ? sanitizeToken(token) : null
        }
        return null
      }
      return (
        tryNode(sel.focusNode, sel.focusOffset) ||
        tryNode(sel.anchorNode, sel.anchorOffset) ||
        null
      )
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

      // No longer hard-fail on multiple words; we will try to pick IOC at caret

      let ioc: string | null = null
      let type: string | null = null
      // 1) Exact selection is a valid IOC
      const directType = identifyIOC(selectedText)
      if (directType) {
        ioc = selectedText
        type = directType
      } else {
        // 2) Try token at caret
        const token = extractTokenFromSelection(selection)
        if (token) {
          const tokType = identifyIOC(token)
          if (tokType) {
            ioc = token
            type = tokType
          }
        }
      }

      // 3) Fallback to first IOC found in selection
      if (!ioc) {
        const iocs = extractIOCs(selectedText)
        if (iocs && iocs.length > 0) {
          ioc = iocs[0]
          type = identifyIOC(ioc)
        }
      }

      if (!ioc || !type) {
        clearSelectionUI()
        return
      }

      const vtSupported = ["IP", "Domain", "URL", "Hash"]
      const abuseSupported = ["IP"]
      const isSupported = vtSupported.includes(type) || abuseSupported.includes(type)
      const hasConfiguredServices = Boolean(availableServices[type]?.length)
      if (!isSupported && !hasConfiguredServices) {
        clearSelectionUI()
        return
      }

      let geometry: SelectionGeometry | null = null
      try {
        geometry = getSelectionGeometry(selection ?? null)
      } catch (err) {
        console.warn("Unable to derive selection rect:", err)
        geometry = null
      }

      const selectionSignature = buildSelectionSignature(selectedText, geometry)
      if (selectionSignature === lastSelectionSignature && currentButton) {
        return
      }
      lastSelectionSignature = selectionSignature

      currentButton?.remove()
      currentMagicButton?.remove()

      const anchorRect = geometry?.caret ?? geometry?.bounds
      if (
        !anchorRect ||
        (!anchorRect.width && !anchorRect.height && anchorRect.top <= 0 && anchorRect.left <= 0)
      ) {
        const activeEl = document.activeElement
        if (
          activeEl instanceof HTMLInputElement ||
          activeEl instanceof HTMLTextAreaElement ||
          (activeEl instanceof HTMLElement && activeEl.isContentEditable)
        ) {
          const caretRect = estimateCaretRect(activeEl) ?? activeEl.getBoundingClientRect()
          geometry = { caret: caretRect, bounds: caretRect }
        } else {
          clearSelectionUI()
          return
        }
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
        currentButton = button
      }

      const magicButton = hasConfiguredServices ? createMagicButton(ioc, () => requestIOCInfo(ioc)) : null
      if (magicButton) {
        document.body.appendChild(magicButton)
        currentMagicButton = magicButton
      }

      if (geometry) {
        positionButtonGroup(geometry)
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

    // Update button positions on any scroll (including nested containers) and resize
    window.addEventListener("scroll", scheduleReposition, { passive: true })
    document.addEventListener("scroll", scheduleReposition, { passive: true, capture: true })
    window.addEventListener("resize", scheduleReposition)

    function repositionButtons() {
      const selection = window.getSelection?.()
      if (!selection) return
      let geometry: SelectionGeometry | null = null
      try {
        geometry = getSelectionGeometry(selection)
      } catch (err) {
        geometry = null
      }
      if (!geometry) return

      positionButtonGroup(geometry)
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
