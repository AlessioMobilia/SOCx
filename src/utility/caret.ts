const MIRROR_STYLE_PROPS = [
  "boxSizing",
  "width",
  "height",
  "overflowX",
  "overflowY",
  "borderTopWidth",
  "borderRightWidth",
  "borderBottomWidth",
  "borderLeftWidth",
  "paddingTop",
  "paddingRight",
  "paddingBottom",
  "paddingLeft",
  "fontStyle",
  "fontVariant",
  "fontWeight",
  "fontStretch",
  "fontSize",
  "fontFamily",
  "lineHeight",
  "textAlign",
  "textTransform",
  "textIndent",
  "letterSpacing",
  "wordSpacing"
] as const

export const estimateCaretRect = (
  inputEl: Element | null,
  positionOverride?: number
): DOMRect | null => {
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

  const doc = inputEl.ownerDocument ?? document
  const computedStyle =
    doc.defaultView?.getComputedStyle(inputEl) ?? getComputedStyle(inputEl)
  const mirrorDiv = doc.createElement("div")

  for (const prop of MIRROR_STYLE_PROPS) {
    mirrorDiv.style.setProperty(prop, computedStyle.getPropertyValue(prop))
  }

  mirrorDiv.style.position = "absolute"
  mirrorDiv.style.visibility = "hidden"
  mirrorDiv.style.whiteSpace =
    inputEl instanceof HTMLTextAreaElement ? "pre-wrap" : "pre"
  mirrorDiv.style.wordWrap = "break-word"
  mirrorDiv.style.wordBreak = "break-word"
  mirrorDiv.style.left = "-9999px"
  mirrorDiv.style.top = "0"
  mirrorDiv.style.overflow = "hidden"

  const selectionEnd =
    typeof positionOverride === "number"
      ? positionOverride
      : typeof inputEl.selectionEnd === "number"
        ? inputEl.selectionEnd
        : inputEl.value.length
  const textBeforeCaret = inputEl.value.substring(0, selectionEnd)

  mirrorDiv.textContent =
    inputEl instanceof HTMLInputElement
      ? textBeforeCaret.replace(/\s/g, "\u00a0")
      : textBeforeCaret

  const marker = doc.createElement("span")
  marker.textContent = "\u200b"
  mirrorDiv.appendChild(marker)
  doc.body.appendChild(mirrorDiv)

  mirrorDiv.scrollTop = inputEl.scrollTop
  mirrorDiv.scrollLeft = inputEl.scrollLeft

  const markerRect = marker.getBoundingClientRect()
  const mirrorRect = mirrorDiv.getBoundingClientRect()
  const inputRect = inputEl.getBoundingClientRect()
  doc.body.removeChild(mirrorDiv)

  const caretLeft =
    inputRect.left + (markerRect.left - mirrorRect.left) - inputEl.scrollLeft
  const caretTop =
    inputRect.top + (markerRect.top - mirrorRect.top) - inputEl.scrollTop
  const lineHeight =
    parseFloat(computedStyle.lineHeight) ||
    markerRect.height ||
    parseFloat(computedStyle.fontSize) ||
    16

  return new DOMRect(caretLeft, caretTop, 0, lineHeight)
}

