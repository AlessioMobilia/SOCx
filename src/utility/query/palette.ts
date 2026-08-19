// The query palette: an in-page overlay that is only ever created when the
// analyst asks for it — keyboard shortcut, context menu entry, or the SOCx UI.
// Nothing is injected on page load, and no floating control is added to the
// host page.

import { showToast } from "../toast"
import { flattenGroupTree, type GroupNode } from "./groups"
import { insertQueryText, resolveTarget, type InsertMode } from "./insertText"
import type { QueryPack, QueryTemplate } from "./packSchema"

const OVERLAY_ATTRIBUTE = "data-socx-query-palette"
const MAX_Z_INDEX = "2147483647"
let activePaletteCleanup: (() => void) | null = null

export type PaletteEntry = {
  key: string
  template: QueryTemplate
  pack: QueryPack
  path: string[]
}

export type PaletteRequest = {
  entries: PaletteEntry[]
  /** Values the palette can offer as the indicator list. */
  indicatorHint?: string[]
  platformLabel?: string
  onRender: (
    entry: PaletteEntry,
    variables: Record<string, string>
  ) => { text: string; note?: string; warning?: string }[]
}

const setStyles = (
  element: HTMLElement,
  styles: Record<string, string>
): void => {
  Object.entries(styles).forEach(([property, value]) => {
    element.style.setProperty(property, value, "important")
  })
}

const isDark = (): boolean =>
  document.documentElement.classList.contains("dark") ||
  document.documentElement.classList.contains("dark-mode") ||
  (typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches)

/** Subsequence match, the same feel as an editor command palette. */
export const fuzzyScore = (haystack: string, needle: string): number => {
  if (!needle) return 1
  const target = haystack.toLowerCase()
  const query = needle.toLowerCase()

  const direct = target.indexOf(query)
  if (direct >= 0) return 1000 - direct

  let score = 0
  let cursor = 0
  for (const character of query) {
    const found = target.indexOf(character, cursor)
    if (found < 0) return 0
    score += found === cursor ? 3 : 1
    cursor = found + 1
  }
  return score
}

export const rankEntries = (
  entries: PaletteEntry[],
  query: string
): PaletteEntry[] => {
  if (!query.trim()) {
    return entries
  }
  return entries
    .map((entry) => {
      const haystack = [
        entry.template.name,
        entry.template.description ?? "",
        entry.path.join(" "),
        entry.pack.name,
        (entry.template.tags ?? []).join(" ")
      ].join(" ")
      return { entry, score: fuzzyScore(haystack, query.trim()) }
    })
    .filter((row) => row.score > 0)
    .sort((a, b) => b.score - a.score)
    .map((row) => row.entry)
}

export const entriesFromTree = (tree: GroupNode[]): PaletteEntry[] =>
  flattenGroupTree(tree).map(({ path, entry }) => ({
    key: entry.key,
    template: entry.template,
    pack: entry.pack,
    path
  }))

export const closePalette = (): void => {
  const cleanup = activePaletteCleanup
  activePaletteCleanup = null
  cleanup?.()
  document
    .querySelectorAll(`[${OVERLAY_ATTRIBUTE}="true"]`)
    .forEach((node) => node.remove())
}

export const isPaletteOpen = (): boolean =>
  Boolean(document.querySelector(`[${OVERLAY_ATTRIBUTE}="true"]`))

export const openPalette = (request: PaletteRequest): void => {
  if (typeof document === "undefined" || !document.documentElement) return
  closePalette()

  // Captured before the overlay steals the focus, so the query can be inserted
  // back into the field the analyst was standing in.
  const insertionTarget = resolveTarget()
  const dark = isDark()
  const font =
    "Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"

  const overlay = document.createElement("div")
  overlay.setAttribute(OVERLAY_ATTRIBUTE, "true")
  setStyles(overlay, {
    all: "initial",
    position: "fixed",
    inset: "0",
    "z-index": MAX_Z_INDEX,
    display: "flex",
    "align-items": "flex-start",
    "justify-content": "center",
    padding: "10vh 16px 16px",
    "background-color": "rgba(15, 23, 42, 0.45)",
    isolation: "isolate"
  })

  const panel = document.createElement("div")
  panel.setAttribute("role", "dialog")
  panel.setAttribute("aria-modal", "true")
  panel.setAttribute("aria-label", "SOCx query palette")
  setStyles(panel, {
    all: "initial",
    display: "flex",
    "flex-direction": "column",
    width: "760px",
    "max-width": "calc(100vw - 32px)",
    "max-height": "76vh",
    "box-sizing": "border-box",
    color: dark ? "#f8fafc" : "#111827",
    "background-color": dark
      ? "rgba(17, 24, 39, 0.99)"
      : "rgba(255, 255, 255, 0.99)",
    border: `1px solid ${dark ? "rgba(255,255,255,0.16)" : "rgba(17,24,39,0.14)"}`,
    "border-top": "4px solid #f5c242",
    "border-radius": "14px",
    "box-shadow": dark
      ? "0 30px 60px rgba(0,0,0,0.6)"
      : "0 30px 60px rgba(15,23,42,0.28)",
    "font-family": font,
    overflow: "hidden"
  })

  // ---------------------------------------------------------------- header
  const header = document.createElement("div")
  setStyles(header, {
    all: "initial",
    display: "flex",
    "align-items": "center",
    gap: "10px",
    padding: "12px 14px",
    "border-bottom": `1px solid ${dark ? "rgba(255,255,255,0.1)" : "rgba(17,24,39,0.08)"}`,
    "font-family": font
  })

  const search = document.createElement("input")
  search.type = "text"
  search.placeholder = request.platformLabel
    ? `Search queries — ${request.platformLabel}`
    : "Search queries"
  setStyles(search, {
    all: "initial",
    flex: "1 1 auto",
    "font-family": font,
    "font-size": "15px",
    color: "inherit",
    "background-color": "transparent",
    border: "0",
    outline: "none",
    "min-width": "0"
  })

  const counter = document.createElement("span")
  setStyles(counter, {
    all: "initial",
    "font-family": font,
    "font-size": "12px",
    color: dark ? "rgba(248,250,252,0.6)" : "rgba(17,24,39,0.55)"
  })

  header.append(search, counter)

  // ------------------------------------------------------------------ body
  const body = document.createElement("div")
  setStyles(body, {
    all: "initial",
    display: "flex",
    flex: "1 1 auto",
    "min-height": "0",
    "font-family": font
  })

  const list = document.createElement("div")
  setStyles(list, {
    all: "initial",
    display: "block",
    width: "44%",
    "overflow-y": "auto",
    "border-right": `1px solid ${dark ? "rgba(255,255,255,0.1)" : "rgba(17,24,39,0.08)"}`,
    "font-family": font
  })

  const preview = document.createElement("div")
  setStyles(preview, {
    all: "initial",
    display: "flex",
    "flex-direction": "column",
    flex: "1 1 auto",
    "min-width": "0",
    "overflow-y": "auto",
    padding: "12px 14px",
    gap: "8px",
    "font-family": font
  })

  body.append(list, preview)

  // ---------------------------------------------------------------- footer
  const footer = document.createElement("div")
  setStyles(footer, {
    all: "initial",
    display: "flex",
    "align-items": "center",
    "justify-content": "space-between",
    gap: "8px",
    padding: "10px 14px",
    "border-top": `1px solid ${dark ? "rgba(255,255,255,0.1)" : "rgba(17,24,39,0.08)"}`,
    "font-family": font
  })

  const hint = document.createElement("span")
  hint.textContent =
    "↑↓ move · Enter insert · Shift+Enter insert at caret · Esc close"
  setStyles(hint, {
    all: "initial",
    "font-family": font,
    "font-size": "11px",
    color: dark ? "rgba(248,250,252,0.55)" : "rgba(17,24,39,0.5)"
  })

  const makeButton = (label: string, primary = false) => {
    const button = document.createElement("button")
    button.type = "button"
    button.textContent = label
    setStyles(button, {
      all: "initial",
      display: "inline-flex",
      "align-items": "center",
      padding: "7px 14px",
      "border-radius": "999px",
      "font-family": font,
      "font-size": "12px",
      "font-weight": "600",
      cursor: "pointer",
      color: primary ? "#111827" : dark ? "#f8fafc" : "#111827",
      "background-color": primary ? "#f5c242" : "transparent",
      border: primary
        ? "1px solid #f5c242"
        : `1px solid ${dark ? "rgba(255,255,255,0.24)" : "rgba(17,24,39,0.18)"}`
    })
    return button
  }

  const copyButton = makeButton("Copy")
  const insertButton = makeButton("Insert", true)
  const actions = document.createElement("div")
  setStyles(actions, { all: "initial", display: "flex", gap: "8px" })
  actions.append(copyButton, insertButton)
  footer.append(hint, actions)

  panel.append(header, body, footer)
  overlay.appendChild(panel)

  // ----------------------------------------------------------------- state
  let filtered = request.entries
  let activeIndex = 0
  const variablesByEntry = new Map<string, Record<string, string>>()
  let rendered: { text: string; note?: string; warning?: string }[] = []

  const renderPreview = () => {
    preview.textContent = ""
    const entry = filtered[activeIndex]
    if (!entry) {
      const empty = document.createElement("p")
      empty.textContent = "No query matches."
      setStyles(empty, {
        all: "initial",
        "font-family": font,
        "font-size": "13px",
        color: dark ? "rgba(248,250,252,0.6)" : "rgba(17,24,39,0.55)"
      })
      preview.appendChild(empty)
      rendered = []
      return
    }
    const variables = variablesByEntry.get(entry.key) ?? {}
    variablesByEntry.set(entry.key, variables)

    const title = document.createElement("p")
    title.textContent = entry.template.name
    setStyles(title, {
      all: "initial",
      "font-family": font,
      "font-size": "14px",
      "font-weight": "600",
      color: "inherit"
    })
    preview.appendChild(title)

    const meta = document.createElement("p")
    meta.textContent = `${entry.path.join(" › ")} · ${entry.pack.name}${
      entry.pack.verified !== true ? " · unverified fields" : ""
    }`
    setStyles(meta, {
      all: "initial",
      "font-family": font,
      "font-size": "11px",
      color: dark ? "rgba(248,250,252,0.6)" : "rgba(17,24,39,0.55)"
    })
    preview.appendChild(meta)

    if (entry.template.description) {
      const description = document.createElement("p")
      description.textContent = entry.template.description
      setStyles(description, {
        all: "initial",
        "font-family": font,
        "font-size": "12px",
        "line-height": "1.45",
        color: dark ? "rgba(248,250,252,0.8)" : "rgba(17,24,39,0.75)"
      })
      preview.appendChild(description)
    }

    // Variable inputs, which are the only input a standard query needs.
    for (const variable of entry.pack.variables ?? []) {
      const row = document.createElement("label")
      setStyles(row, {
        all: "initial",
        display: "flex",
        "align-items": "center",
        gap: "8px",
        "font-family": font,
        "font-size": "12px",
        color: "inherit"
      })
      const label = document.createElement("span")
      label.textContent = variable.label
      setStyles(label, {
        all: "initial",
        "font-family": font,
        "font-size": "12px",
        "min-width": "110px",
        color: dark ? "rgba(248,250,252,0.75)" : "rgba(17,24,39,0.7)"
      })

      const input = variable.options?.length
        ? document.createElement("select")
        : document.createElement("input")
      setStyles(input, {
        all: "initial",
        "font-family": font,
        "font-size": "12px",
        color: "inherit",
        "background-color": dark
          ? "rgba(255,255,255,0.06)"
          : "rgba(17,24,39,0.04)",
        border: `1px solid ${dark ? "rgba(255,255,255,0.16)" : "rgba(17,24,39,0.14)"}`,
        "border-radius": "8px",
        padding: "5px 8px",
        flex: "1 1 auto",
        "min-width": "0"
      })

      const current = variables[variable.id] ?? variable.default ?? ""
      if (input instanceof HTMLSelectElement) {
        for (const option of variable.options ?? []) {
          const element = document.createElement("option")
          element.value = option
          element.textContent = option
          input.appendChild(element)
        }
        input.value = current
      } else {
        ;(input as HTMLInputElement).value = current
      }

      input.addEventListener("input", () => {
        variables[variable.id] = (input as HTMLInputElement).value
        renderPreview()
      })
      input.addEventListener("change", () => {
        variables[variable.id] = (input as HTMLInputElement).value
        renderPreview()
      })

      row.append(label, input)
      preview.appendChild(row)
    }

    rendered = request.onRender(entry, variables)

    if (rendered.length === 0) {
      const empty = document.createElement("p")
      empty.textContent =
        "This template needs indicators of a type the current selection does not contain."
      setStyles(empty, {
        all: "initial",
        "font-family": font,
        "font-size": "12px",
        color: "#f59e0b"
      })
      preview.appendChild(empty)
      return
    }

    rendered.forEach((query) => {
      if (query.warning) {
        const warning = document.createElement("p")
        warning.textContent = query.warning
        setStyles(warning, {
          all: "initial",
          "font-family": font,
          "font-size": "11px",
          color: "#f59e0b"
        })
        preview.appendChild(warning)
      }
      if (query.note) {
        const note = document.createElement("p")
        note.textContent = query.note
        setStyles(note, {
          all: "initial",
          "font-family": font,
          "font-size": "11px",
          color: dark ? "rgba(248,250,252,0.55)" : "rgba(17,24,39,0.5)"
        })
        preview.appendChild(note)
      }
      const code = document.createElement("pre")
      code.textContent = query.text
      setStyles(code, {
        all: "initial",
        display: "block",
        "font-family":
          "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
        "font-size": "12px",
        "line-height": "1.45",
        "white-space": "pre-wrap",
        "word-break": "break-word",
        padding: "10px",
        "border-radius": "10px",
        color: "inherit",
        "background-color": dark
          ? "rgba(255,255,255,0.05)"
          : "rgba(17,24,39,0.04)"
      })
      preview.appendChild(code)
    })
  }

  const renderList = () => {
    list.textContent = ""
    counter.textContent = `${filtered.length} / ${request.entries.length}`

    let lastPath = ""
    filtered.forEach((entry, index) => {
      const pathLabel = entry.path.join(" › ")
      if (pathLabel !== lastPath) {
        lastPath = pathLabel
        const heading = document.createElement("p")
        heading.textContent = pathLabel
        setStyles(heading, {
          all: "initial",
          display: "block",
          padding: "10px 14px 4px",
          "font-family": font,
          "font-size": "10px",
          "font-weight": "700",
          "letter-spacing": "0.12em",
          "text-transform": "uppercase",
          color: dark ? "rgba(248,250,252,0.45)" : "rgba(17,24,39,0.45)"
        })
        list.appendChild(heading)
      }

      const item = document.createElement("div")
      item.textContent = entry.template.name
      item.setAttribute("data-index", String(index))
      setStyles(item, {
        all: "initial",
        display: "block",
        padding: "7px 14px",
        "font-family": font,
        "font-size": "13px",
        cursor: "pointer",
        color: "inherit",
        "background-color":
          index === activeIndex
            ? dark
              ? "rgba(245,194,66,0.18)"
              : "rgba(245,194,66,0.28)"
            : "transparent"
      })
      item.addEventListener("click", () => {
        activeIndex = index
        renderList()
        renderPreview()
      })
      item.addEventListener("dblclick", () => void insert("replace"))
      list.appendChild(item)
    })

    const active = list.querySelector(`[data-index="${activeIndex}"]`)
    active?.scrollIntoView({ block: "nearest" })
  }

  const currentText = (): string =>
    rendered.map((query) => query.text).join("\n\n")

  const insert = async (mode: InsertMode) => {
    const text = currentText()
    if (!text) return
    closePalette()
    const result = await insertQueryText(text, mode, insertionTarget)
    if (result.method === "clipboard") {
      showToast("Query copied — paste it with Ctrl+V", "info")
    } else if (!result.success) {
      showToast("Could not insert the query", "danger")
    } else {
      showToast("Query inserted", "success")
    }
  }

  const copy = async () => {
    const text = currentText()
    if (!text) return
    try {
      await navigator.clipboard.writeText(text)
      closePalette()
      showToast("Query copied to clipboard", "success")
    } catch {
      showToast("Could not copy the query", "danger")
    }
  }

  insertButton.addEventListener("click", () => void insert("replace"))
  copyButton.addEventListener("click", () => void copy())

  search.addEventListener("input", () => {
    filtered = rankEntries(request.entries, search.value)
    activeIndex = 0
    renderList()
    renderPreview()
  })

  const onKeyDown = (event: KeyboardEvent) => {
    if (event.key === "Escape") {
      event.preventDefault()
      event.stopPropagation()
      cleanup()
      return
    }
    if (event.key === "ArrowDown" || (event.key === "n" && event.ctrlKey)) {
      event.preventDefault()
      activeIndex = Math.min(activeIndex + 1, filtered.length - 1)
      renderList()
      renderPreview()
      return
    }
    if (event.key === "ArrowUp" || (event.key === "p" && event.ctrlKey)) {
      event.preventDefault()
      activeIndex = Math.max(activeIndex - 1, 0)
      renderList()
      renderPreview()
      return
    }
    if (event.key === "Enter") {
      event.preventDefault()
      void insert(event.shiftKey ? "caret" : "replace")
    }
  }

  const cleanup = () => {
    document.removeEventListener("keydown", onKeyDown, true)
    overlay.remove()
    if (activePaletteCleanup === cleanup) {
      activePaletteCleanup = null
    }
  }

  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) cleanup()
  })
  document.addEventListener("keydown", onKeyDown, true)
  activePaletteCleanup = cleanup

  ;(document.body ?? document.documentElement).appendChild(overlay)
  renderList()
  renderPreview()
  search.focus()
}
