// Inserting a query into the search bar of a SIEM console.
//
// These bars are almost never plain inputs: they are React controlled inputs,
// CodeMirror instances or the hidden textarea Monaco renders behind its editor.
// Assigning `element.value` does not work — the framework overwrites it on the
// next render — so the strategies below go from the most faithful to the most
// defensive, and the last one always succeeds because it falls back to the
// clipboard.

export type InsertMode = "replace" | "caret"

export type InsertResult = {
  method: "exec-command" | "native-setter" | "clipboard" | "none"
  success: boolean
  error?: string
}

const EDITABLE_SELECTOR =
  'input:not([type=checkbox]):not([type=radio]):not([type=button]):not([type=submit]), textarea, [contenteditable=""], [contenteditable="true"]'

const isEditable = (element: Element | null): element is HTMLElement => {
  if (!element) return false
  if (element instanceof HTMLTextAreaElement) return !element.readOnly
  if (element instanceof HTMLInputElement) {
    return (
      !element.readOnly &&
      !/^(checkbox|radio|button|submit|file)$/i.test(element.type)
    )
  }
  return (element as HTMLElement).isContentEditable === true
}

/**
 * The element the analyst right clicked, captured on `contextmenu` because the
 * focus can move between opening the menu and clicking an item.
 */
let lastEditableTarget: HTMLElement | null = null

export const rememberEditableTarget = (target: EventTarget | null): void => {
  if (target instanceof Element) {
    const editable = target.closest(EDITABLE_SELECTOR)
    if (isEditable(editable)) {
      lastEditableTarget = editable as HTMLElement
      return
    }
  }
  if (isEditable(document.activeElement)) {
    lastEditableTarget = document.activeElement as HTMLElement
  }
}

export const resolveTarget = (): HTMLElement | null => {
  if (isEditable(document.activeElement)) {
    return document.activeElement as HTMLElement
  }
  if (lastEditableTarget?.isConnected) {
    return lastEditableTarget
  }
  // Last resort: the biggest editable on the page, which on a console is the
  // query bar in the overwhelming majority of cases.
  const candidates = Array.from(
    document.querySelectorAll<HTMLElement>(EDITABLE_SELECTOR)
  ).filter(isEditable)
  if (candidates.length === 0) return null
  return candidates.sort(
    (a, b) =>
      b.getBoundingClientRect().width * b.getBoundingClientRect().height -
      a.getBoundingClientRect().width * a.getBoundingClientRect().height
  )[0]
}

const selectAll = (element: HTMLElement): void => {
  if (
    element instanceof HTMLInputElement ||
    element instanceof HTMLTextAreaElement
  ) {
    element.select()
    return
  }
  const range = document.createRange()
  range.selectNodeContents(element)
  const selection = window.getSelection()
  selection?.removeAllRanges()
  selection?.addRange(range)
}

const withNativeSetter = (element: HTMLElement, text: string): boolean => {
  const prototype =
    element instanceof HTMLTextAreaElement
      ? HTMLTextAreaElement.prototype
      : element instanceof HTMLInputElement
        ? HTMLInputElement.prototype
        : null
  if (!prototype) return false

  const descriptor = Object.getOwnPropertyDescriptor(prototype, "value")
  if (!descriptor?.set) return false

  descriptor.set.call(element, text)
  element.dispatchEvent(new Event("input", { bubbles: true }))
  element.dispatchEvent(new Event("change", { bubbles: true }))
  return true
}

export const insertQueryText = async (
  text: string,
  mode: InsertMode = "replace",
  target: HTMLElement | null = resolveTarget()
): Promise<InsertResult> => {
  if (!target) {
    return copyAsFallback(text, "no editable field found on the page")
  }

  try {
    target.focus({ preventScroll: true })
    if (mode === "replace") {
      selectAll(target)
    }

    // execCommand is deprecated but remains the only insertion that produces
    // real beforeinput/input events, so React, CodeMirror and Monaco all see
    // it, and the page keeps a working undo stack.
    const inserted = document.execCommand("insertText", false, text)
    if (inserted) {
      return { method: "exec-command", success: true }
    }

    if (mode === "replace" && withNativeSetter(target, text)) {
      return { method: "native-setter", success: true }
    }
  } catch (error) {
    return copyAsFallback(
      text,
      error instanceof Error ? error.message : "insertion failed"
    )
  }

  return copyAsFallback(text, "the field rejected the insertion")
}

const copyAsFallback = async (
  text: string,
  reason: string
): Promise<InsertResult> => {
  try {
    await navigator.clipboard.writeText(text)
    return { method: "clipboard", success: true, error: reason }
  } catch {
    return { method: "none", success: false, error: reason }
  }
}
