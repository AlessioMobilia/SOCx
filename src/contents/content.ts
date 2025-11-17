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
const HIDDEN_CHAR_REGEX =
  /[\p{Cf}\p{Cc}\u00A0\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180D\u200B-\u200F\u2028-\u202E\u2060-\u206F\uFEFF\uFFF9-\uFFFC]/gu
const NON_ASCII_REGEX = /[^\x20-\x7E]/g
const availableServices = servicesConfig.availableServices as Record<string, string[]>

  // inizializzazione sicura
  if (!(window as any)._formatScriptInitialized) {
    ;(window as any)._formatScriptInitialized = true
    // Controlla se siamo nell'iframe o nella finestra principale
    const isInIframe = window.self !== window.top;





    let buttonGroup: HTMLDivElement | null = null
    let lastSelectionSignature: string | null = null
    let lastValidSelection: Selection | null = null
    let repositionScheduled = false
    let lastInteractionRect: DOMRect | null = null
    let lastPointerRect: DOMRect | null = null
    const BUTTON_INTERACTION_SUSPEND_MS = 350
    let lastButtonInteractionAt = 0

    const now = () =>
      typeof performance !== "undefined" && performance.now ? performance.now() : Date.now()

    const markButtonInteraction = () => {
      lastButtonInteractionAt = now()
    }

    const shouldSkipDueToButtonInteraction = () =>
      now() - lastButtonInteractionAt < BUTTON_INTERACTION_SUSPEND_MS

    const debouncedMouseSelection = debounce((event?: MouseEvent) => handleSelection(event), 180)
    const deferredSelectionEvaluation = debounce(() => handleSelection(), 120)

    document.addEventListener("mouseup", (event) => debouncedMouseSelection(event as MouseEvent))
    document.addEventListener(
      "pointerup",
      (event) => debouncedMouseSelection(event as MouseEvent),
      true
    )
    document.addEventListener("selectionchange", handleSelectionChange)

    const destroyButtonGroup = () => {
      buttonGroup?.remove()
      buttonGroup = null
    }

    const clearSelectionUI = () => {
      if (!buttonGroup && !lastSelectionSignature) {
        return
      }

      destroyButtonGroup()
      lastSelectionSignature = null
      lastInteractionRect = null
      lastPointerRect = null
    }

    function handleSelectionChange(event?: Event) {
      if (shouldSkipDueToButtonInteraction()) {
        return
      }
      const selection = getActiveSelection(event)
      const hasDomSelection = hasUsableSelection(selection)
      const hasInputSelection = Boolean(getInputSelection(getDeepActiveElement()))
      if (!hasDomSelection && !hasInputSelection) {
        lastValidSelection = null
        clearSelectionUI()
        return
      }
      if (hasDomSelection) {
        lastValidSelection = selection
      }
      deferredSelectionEvaluation()
    }

    const clampValue = (value: number, min: number, max: number) =>
      Math.min(Math.max(value, min), max)

    const clampToViewport = (
      coords: { left: number; top: number },
      width: number,
      height: number
    ) => {
      const docEl = document.documentElement
      const maxLeft = Math.max(BUTTON_MARGIN, docEl.clientWidth - width - BUTTON_MARGIN)
      const maxTop = Math.max(BUTTON_MARGIN, docEl.clientHeight - height - BUTTON_MARGIN)
      return {
        left: clampValue(coords.left, BUTTON_MARGIN, maxLeft),
        top: clampValue(coords.top, BUTTON_MARGIN, maxTop)
      }
    }

    const getDeepActiveElement = (): Element | null => {
      let active: Element | null = document.activeElement
      while (active instanceof HTMLElement && active.shadowRoot?.activeElement) {
        active = active.shadowRoot.activeElement
      }
      return active
    }

    type InputSelectionContext = {
      element: HTMLInputElement | HTMLTextAreaElement
      start: number
      end: number
      text: string
    }

    const getInputSelection = (
      element: Element | null
    ): InputSelectionContext | null => {
      if (element instanceof HTMLTextAreaElement) {
        const { selectionStart, selectionEnd, value } = element
        if (
          selectionStart === null ||
          selectionEnd === null ||
          selectionStart === selectionEnd
        ) {
          return null
        }
        const text = value.slice(selectionStart, selectionEnd)
        return text
          ? {
              element,
              start: selectionStart,
              end: selectionEnd,
              text
            }
          : null
      }

      if (element instanceof HTMLInputElement) {
        const { selectionStart, selectionEnd, value } = element
        if (
          selectionStart === null ||
          selectionEnd === null ||
          selectionStart === selectionEnd
        ) {
          return null
        }
        const text = value.slice(selectionStart, selectionEnd)
        return text
          ? {
              element,
              start: selectionStart,
              end: selectionEnd,
              text
            }
          : null
      }

      return null
    }

    const hasUsableSelection = (selection: Selection | null): selection is Selection =>
      Boolean(selection && selection.rangeCount > 0 && !selection.isCollapsed)

    const getSelectionFromRootNode = (root: Node | null): Selection | null => {
      if (!root) {
        return null
      }
      if (root instanceof Document) {
        return root.getSelection()
      }
      if (root instanceof ShadowRoot) {
        const getSelectionFn = (root as ShadowRoot & {
          getSelection?: () => Selection | null
        }).getSelection
        return typeof getSelectionFn === "function" ? getSelectionFn.call(root) : null
      }
      return null
    }

    const getSelectionFromEventPath = (event?: Event): Selection | null => {
      if (typeof event?.composedPath !== "function") {
        return null
      }
      for (const entry of event.composedPath()) {
        if (entry instanceof Node) {
          const rootNode = entry.getRootNode?.() ?? null
          const selection = getSelectionFromRootNode(rootNode)
          if (hasUsableSelection(selection)) {
            return selection
          }
        }
      }
      return null
    }

    const getSelectionFromActiveNode = (): Selection | null => {
      const active = getDeepActiveElement()
      if (!active) {
        return null
      }
      return getSelectionFromRootNode(active.getRootNode?.() ?? null)
    }

    const getActiveSelection = (event?: Event): Selection | null => {
      const docSelection = window.getSelection()
      if (hasUsableSelection(docSelection)) {
        return docSelection
      }
      const eventSelection = getSelectionFromEventPath(event)
      if (hasUsableSelection(eventSelection)) {
        return eventSelection
      }
      const activeSelection = getSelectionFromActiveNode()
      if (hasUsableSelection(activeSelection)) {
        return activeSelection
      }
      return docSelection
    }

    const isEventFromButtonUI = (event?: Event | null): boolean => {
      if (!event || !buttonGroup) {
        return false
      }
      if (typeof event.composedPath === "function") {
        return event
          .composedPath()
          .some(
            (node) =>
              node === buttonGroup ||
              (node instanceof Node && buttonGroup.contains(node))
          )
      }
      const target = event.target
      return target instanceof Node ? buttonGroup.contains(target) : false
    }

    const getEventPointerRect = (event?: MouseEvent | PointerEvent | null): DOMRect | null => {
      if (!event || typeof event.clientX !== "number" || typeof event.clientY !== "number") {
        return null
      }
      return new DOMRect(event.clientX, event.clientY, 1, 1)
    }

    const getEventTargetRect = (event?: Event): DOMRect | null => {
      if (!event) {
        return null
      }
      const target = event.target
      if (target instanceof Element) {
        return target.getBoundingClientRect()
      }
      return null
    }

    const prepareFloatingButton = (button: HTMLButtonElement) => {
      button.style.position = "static"
      button.style.margin = "0"
      button.style.flex = "0 0 auto"
    }

    const mountButtonGroup = (buttons: HTMLButtonElement[]) => {
      destroyButtonGroup()
      if (!buttons.length) return

      const container = document.createElement("div")
      container.id = "socx-floating-actions"
      container.style.position = "fixed"
      container.style.display = "flex"
      container.style.alignItems = "center"
      container.style.gap = `${MAGIC_BUTTON_GAP}px`
      container.style.zIndex = "2147483647"
      container.style.visibility = "hidden"
      container.style.pointerEvents = "auto"

      buttons.forEach((button) => {
        prepareFloatingButton(button)
        container.appendChild(button)
      })

      const registerInteraction = () => markButtonInteraction()
      container.addEventListener("pointerdown", registerInteraction, true)
      container.addEventListener("pointerup", registerInteraction, true)
      container.addEventListener("click", registerInteraction, true)
      container.addEventListener("contextmenu", registerInteraction, true)

      document.body.appendChild(container)
      buttonGroup = container
    }

    function positionButtonGroup(geometry: SelectionGeometry | null) {
      if (!buttonGroup || !geometry) {
        return
      }

      const anchorRect = geometry.caret ?? geometry.bounds
      const selectionRect = geometry.bounds ?? geometry.caret
      if (!anchorRect || !selectionRect) {
        return
      }

      const groupWidth =
        buttonGroup.offsetWidth ||
        buttonGroup.getBoundingClientRect().width ||
        28
      const groupHeight =
        buttonGroup.offsetHeight ||
        buttonGroup.getBoundingClientRect().height ||
        28

      const verticalCenter = anchorRect.top + (anchorRect.height - groupHeight) / 2
      const horizontalCenter = anchorRect.left + (anchorRect.width - groupWidth) / 2

      const candidates = [
        { left: selectionRect.right + BUTTON_OFFSET, top: verticalCenter },
        { left: selectionRect.left - BUTTON_OFFSET - groupWidth, top: verticalCenter },
        { left: horizontalCenter, top: selectionRect.bottom + BUTTON_OFFSET },
        { left: horizontalCenter, top: selectionRect.top - BUTTON_OFFSET - groupHeight }
      ]

      let bestPlacement = clampToViewport(candidates[0], groupWidth, groupHeight)
      let smallestAdjustment = Number.POSITIVE_INFINITY

      for (const candidate of candidates) {
        const clamped = clampToViewport(candidate, groupWidth, groupHeight)
        const adjustment =
          Math.abs(clamped.left - candidate.left) + Math.abs(clamped.top - candidate.top)
        if (adjustment < smallestAdjustment) {
          smallestAdjustment = adjustment
          bestPlacement = clamped
          if (adjustment === 0) {
            break
          }
        }
      }

      buttonGroup.style.left = `${bestPlacement.left}px`
      buttonGroup.style.top = `${bestPlacement.top}px`
      buttonGroup.style.visibility = "visible"
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

    const mergeRectList = (rects: DOMRectList | DOMRect[]): DOMRect | null => {
      let minLeft = Number.POSITIVE_INFINITY
      let minTop = Number.POSITIVE_INFINITY
      let maxRight = Number.NEGATIVE_INFINITY
      let maxBottom = Number.NEGATIVE_INFINITY
      let found = false

      const visit = (rect: DOMRect) => {
        if (rect.width || rect.height) {
          found = true
          if (rect.left < minLeft) minLeft = rect.left
          if (rect.top < minTop) minTop = rect.top
          if (rect.right > maxRight) maxRight = rect.right
          if (rect.bottom > maxBottom) maxBottom = rect.bottom
        }
      }

      const list = Array.isArray(rects) ? rects : Array.from(rects)
      list.forEach(visit)

      if (!found) {
        return null
      }
      return new DOMRect(
        minLeft,
        minTop,
        Math.max(0, maxRight - minLeft),
        Math.max(0, maxBottom - minTop)
      )
    }

    const getRangeRect = (range: Range): DOMRect | null => {
      const rects = range.getClientRects()
      const merged = mergeRectList(rects)
      if (merged) {
        return merged
      }
      const fallbackRect = range.getBoundingClientRect()
      if (fallbackRect.width || fallbackRect.height) {
        return fallbackRect
      }
      return null
    }

    const isUsableRect = (rect: DOMRect | null) =>
      Boolean(rect && (rect.width > 0 || rect.height > 0 || rect.top > 0 || rect.left > 0))

    const getSelectionGeometry = (
      selection: Selection | null,
      inputSelection: InputSelectionContext | null,
      fallbackRect?: DOMRect | null
    ): SelectionGeometry | null => {
      let caretRect: DOMRect | null = null
      let boundsRect: DOMRect | null = null

      if (inputSelection) {
        const caretEstimate =
          estimateCaretRect(inputSelection.element) ??
          inputSelection.element.getBoundingClientRect()
        caretRect = caretEstimate
        boundsRect = caretEstimate
        return { caret: caretRect, bounds: boundsRect }
      }

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
        const rangeRect = getRangeRect(range)
        if (rangeRect?.width || rangeRect?.height) {
          boundsRect = rangeRect
        }
      }

      const caretUsable = isUsableRect(caretRect)
      const boundsUsable = isUsableRect(boundsRect)

      if (!caretUsable && fallbackRect) {
        caretRect = fallbackRect
      }

      if (!boundsUsable && caretRect) {
        boundsRect = caretRect
      }

      if (!isUsableRect(caretRect) && !isUsableRect(boundsRect)) {
        return null
      }

      if (!caretRect && boundsRect) {
        caretRect = boundsRect
      }
      if (!boundsRect && caretRect) {
        boundsRect = caretRect
      }

      return { caret: caretRect, bounds: boundsRect }
    }

    const stripHiddenChars = (value: string): string => value.replace(HIDDEN_CHAR_REGEX, "")
    const asciiSafe = (value: string): string =>
      stripHiddenChars(value).normalize("NFKC").replace(NON_ASCII_REGEX, "")

    const sanitizeToken = (raw: string): string =>
      asciiSafe(raw).replace(/^\W+|\W+$/g, "")

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

    const extractTokenFromInputSelection = (
      context: InputSelectionContext | null
    ): string | null => {
      if (!context) return null
      const value = context.element.value
      const caretIndex = clampValue(context.end, 0, value.length)
      let start = caretIndex
      let end = caretIndex
      const isAllowed = (ch: string) => /[A-Za-z0-9_:\.\-\/\%]/.test(ch)
      while (start > 0 && isAllowed(value[start - 1])) start--
      while (end < value.length && isAllowed(value[end])) end++
      const token = value.slice(start, end)
      return token ? sanitizeToken(token) : null
    }

    async function handleSelection(event?: MouseEvent) {
      if (isEventFromButtonUI(event) || shouldSkipDueToButtonInteraction()) {
        return
      }

      const rawSelection = getActiveSelection(event)
      const selection = hasUsableSelection(rawSelection) ? rawSelection : null
      const activeElement = getDeepActiveElement()
      const inputSelection = getInputSelection(activeElement)
      const pointerRect = getEventPointerRect(event)
      if (pointerRect) {
        lastPointerRect = pointerRect
      }
      const targetRect = getEventTargetRect(event)
      const fallbackRect =
        pointerRect ?? targetRect ?? lastPointerRect ?? lastInteractionRect

      const rawText = rawSelection?.toString() ?? inputSelection?.text ?? ""
      const selectedText = asciiSafe(rawText).trim()
      if (!selectedText) {
        lastValidSelection = null
        clearSelectionUI()
        return
      }

      lastValidSelection = selection

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
        const token =
          extractTokenFromSelection(selection) ||
          extractTokenFromInputSelection(inputSelection)
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

      const selectionMatchesIOC = selectedText === ioc
      const selectionIncludesWhitespace = /\s/.test(selectedText)
      const selectionLongerThanIOC = selectedText.length > ioc.length
      if (
        !selectionMatchesIOC &&
        selectionLongerThanIOC &&
        (selectionIncludesWhitespace || selectedText.length - ioc.length > 3)
      ) {
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
        geometry = getSelectionGeometry(selection, inputSelection, fallbackRect)
      } catch (err) {
        console.warn("Unable to derive selection rect:", err)
        geometry = null
      }

      if (!geometry) {
        clearSelectionUI()
        return
      }

      const resolvedAnchor = geometry.caret ?? geometry.bounds ?? fallbackRect
      if (resolvedAnchor) {
        lastInteractionRect = resolvedAnchor
      }

      const selectionSignature = buildSelectionSignature(selectedText, geometry)
      if (selectionSignature === lastSelectionSignature && buttonGroup) {
        positionButtonGroup(geometry)
        return
      }
      lastSelectionSignature = selectionSignature

      destroyButtonGroup()

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

      const buttonsToShow: HTMLButtonElement[] = []
      if (button) {
        buttonsToShow.push(button)
      }

      const magicButton = hasConfiguredServices ? createMagicButton(ioc, () => requestIOCInfo(ioc)) : null
      if (magicButton) {
        buttonsToShow.push(magicButton)
      }

      if (!buttonsToShow.length) {
        clearSelectionUI()
        return
      }

      mountButtonGroup(buttonsToShow)
      positionButtonGroup(geometry)
    }




    const scheduleReposition = () => {
      if (repositionScheduled || !buttonGroup) return
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
      if (!buttonGroup || shouldSkipDueToButtonInteraction()) return
      let selection = getActiveSelection()
      if (!hasUsableSelection(selection)) {
        selection = hasUsableSelection(lastValidSelection) ? lastValidSelection : null
      }
      const activeElement = getDeepActiveElement()
      const inputSelection = getInputSelection(activeElement)
      let geometry: SelectionGeometry | null = null
      try {
        geometry = getSelectionGeometry(
          selection,
          inputSelection,
          lastInteractionRect ?? lastPointerRect
        )
      } catch (err) {
        geometry = null
      }
      if (!geometry) return

      const anchorRect = geometry.caret ?? geometry.bounds
      if (anchorRect) {
        lastInteractionRect = anchorRect
      }
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
        const formattedText = lastValidSelection ? formatSelectedText(lastValidSelection) : ""
        sendResponse({ success: true, formatted: formattedText })
        return false;
      }
    })

  }
