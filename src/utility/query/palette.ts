// The shared query browser. It mounts as an in-page overlay only when the
// analyst asks for the palette, or as the main region of Query workspace.
// Nothing is injected into a host page on load and no floating control is
// added.
//
// The overlay lives in a hostile styling environment, so every node is built
// from `all: initial` plus explicit `!important` declarations rather than from
// a stylesheet the host page could reach.

import { showToast } from "../toast"
import { toggleFavoriteKey } from "./favorites"
import { flattenGroupTree, type GroupNode } from "./groups"
import { insertQueryText, resolveTarget, type InsertMode } from "./insertText"
import {
  templateVariables,
  type QueryPack,
  type QueryTemplate
} from "./packSchema"
import {
  ALL_FILTERS,
  applyPaletteFilters,
  buildFacets,
  dialectChipLabel,
  entryDialect,
  FAVORITES_LABEL,
  hasActiveFilters,
  KIND_LABELS,
  resolveEntryLabels,
  type PaletteFilterState
} from "./paletteFilters"

export { fuzzyScore, rankEntries } from "./paletteFilters"

const OVERLAY_ATTRIBUTE = "data-socx-query-palette"
const MAX_Z_INDEX = "2147483647"
/** How many rows are drawn before the list asks to be expanded. */
const PAGE_SIZE = 40
/** Above this many languages a chip row stops being readable. */
const MAX_DIALECT_CHIPS = 6
let activePaletteCleanup: (() => void) | null = null

export type PaletteEntry = {
  key: string
  template: QueryTemplate
  pack: QueryPack
  path: string[]
}

export type PaletteRequest = {
  entries: PaletteEntry[]
  /** Initial content of the indicator field: selection, or Bulk Check. */
  indicatorHint?: string[]
  /** One line summary of what the indicator field currently parses to. */
  describeIndicators?: (indicatorText: string) => string
  /** Start with the per-type comparisons merged into one query. */
  mergeTypes?: boolean
  onMergeTypesChange?: (value: boolean) => void
  /** Keeps an embedding surface's draft alive if the library is remounted. */
  onIndicatorTextChange?: (value: string) => void
  /** Keeps the current template alive if the library is remounted. */
  onSelectedKeyChange?: (key: string) => void
  platformLabel?: string
  /** Starred entry keys, most recently starred first. */
  favorites?: string[]
  /** Entry to open on, e.g. the template a context menu entry named. */
  initialKey?: string
  /** Dialect id to human label, used for the language chip tooltips. */
  dialectLabels?: Map<string, string>
  onToggleFavorite?: (key: string, favorites: string[]) => void
  onRender: (
    entry: PaletteEntry,
    input: {
      variables: Record<string, string>
      indicatorText: string
      mergeTypes: boolean
    }
  ) => { text: string; note?: string; warning?: string }[]
}

export type QueryViewMode = "overlay" | "workspace"

export type QueryViewOptions = {
  mode: QueryViewMode
  host: HTMLElement
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

/**
 * Mounts the one query browser used by both the in-page palette and the
 * dedicated workspace. The mode only changes the surrounding chrome and the
 * actions that make sense in that context; catalogue, filters and preview stay
 * identical.
 */
export const mountQueryView = (
  request: PaletteRequest,
  options: QueryViewOptions
): (() => void) => {
  if (typeof document === "undefined" || !document.documentElement) {
    return () => undefined
  }
  const embedded = options.mode === "workspace"
  if (!embedded) closePalette()

  // Captured before the overlay steals the focus, so the query can be inserted
  // back into the field the analyst was standing in.
  const insertionTarget = embedded ? null : resolveTarget()
  const dark = isDark()
  const font =
    "Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
  const mono = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

  // The SOCx palette: one accent, two neutrals, and translucency for
  // everything in between, so the overlay reads the same on a light and on a
  // dark console.
  const ink = dark ? "#f4f7ff" : "#111322"
  const muted = dark ? "rgba(244,247,255,0.62)" : "rgba(17,19,34,0.58)"
  const faint = dark ? "rgba(244,247,255,0.45)" : "rgba(17,19,34,0.45)"
  const line = dark ? "rgba(255,255,255,0.10)" : "rgba(17,19,34,0.09)"
  const strongLine = dark ? "rgba(255,255,255,0.20)" : "rgba(17,19,34,0.16)"
  const fill = dark ? "rgba(255,255,255,0.06)" : "rgba(17,19,34,0.04)"
  const accent = "#f5c242"
  const accentSoft = dark ? "rgba(245,194,66,0.18)" : "rgba(245,194,66,0.22)"
  const warn = "#f59e0b"

  const overlay = document.createElement("div")
  overlay.setAttribute(OVERLAY_ATTRIBUTE, embedded ? "workspace" : "true")
  setStyles(overlay, {
    all: "initial",
    position: embedded ? "relative" : "fixed",
    inset: embedded ? "auto" : "0",
    "z-index": embedded ? "1" : MAX_Z_INDEX,
    display: "flex",
    "align-items": "flex-start",
    "justify-content": "center",
    width: "100%",
    height: embedded ? "100%" : "auto",
    "min-height": "0",
    "box-sizing": "border-box",
    padding: embedded ? "0" : "4vh 16px 16px",
    "background-color": embedded
      ? "transparent"
      : dark
        ? "rgba(2, 6, 16, 0.6)"
        : "rgba(15, 23, 42, 0.42)",
    isolation: "isolate"
  })

  const panel = document.createElement("div")
  panel.setAttribute("role", embedded ? "region" : "dialog")
  if (!embedded) panel.setAttribute("aria-modal", "true")
  panel.setAttribute(
    "aria-label",
    embedded ? "SOCx query workspace" : "SOCx query palette"
  )
  setStyles(panel, {
    all: "initial",
    display: "flex",
    "flex-direction": "column",
    width: embedded ? "100%" : "1180px",
    height: embedded ? "100%" : "auto",
    "max-width": embedded ? "none" : "calc(100vw - 32px)",
    "max-height": embedded ? "none" : "90vh",
    "box-sizing": "border-box",
    color: ink,
    "background-color": dark
      ? "rgba(13, 21, 36, 0.99)"
      : "rgba(255, 255, 255, 0.99)",
    border: `1px solid ${strongLine}`,
    "border-top": `3px solid ${accent}`,
    "border-radius": embedded ? "14px" : "16px",
    "box-shadow": embedded
      ? "0 8px 24px rgba(15,23,42,0.08)"
      : dark
        ? "0 32px 64px rgba(0,0,0,0.62)"
        : "0 32px 64px rgba(15,23,42,0.26)",
    "font-family": font,
    overflow: "hidden"
  })

  // -------------------------------------------------------- small factories

  const makeText = (
    tag: keyof HTMLElementTagNameMap,
    text: string,
    styles: Record<string, string>
  ): HTMLElement => {
    const element = document.createElement(tag)
    element.textContent = text
    setStyles(element, { all: "initial", "font-family": font, ...styles })
    return element
  }

  const makeBadge = (text: string, tone: "neutral" | "accent" | "warn") =>
    makeText("span", text, {
      display: "inline-flex",
      "align-items": "center",
      padding: "2px 8px",
      "border-radius": "999px",
      "font-size": "10px",
      "font-weight": "700",
      "letter-spacing": "0.06em",
      "text-transform": "uppercase",
      color: tone === "warn" ? warn : tone === "accent" ? ink : muted,
      "background-color":
        tone === "accent"
          ? accentSoft
          : tone === "warn"
            ? "rgba(245,158,11,0.14)"
            : fill
    })

  const makeChip = (options: {
    label: string
    count?: number
    active: boolean
    /** Still on screen, but nothing matches it right now. */
    dimmed?: boolean
    title?: string
    onClick: () => void
  }) => {
    const chip = document.createElement("button")
    chip.type = "button"
    chip.setAttribute("aria-pressed", String(options.active))
    if (options.title) chip.title = options.title
    setStyles(chip, {
      all: "initial",
      display: "inline-flex",
      "align-items": "center",
      gap: "6px",
      padding: "4px 10px",
      "border-radius": "999px",
      "font-family": font,
      "font-size": "11px",
      "font-weight": "600",
      "white-space": "nowrap",
      cursor: "pointer",
      opacity: options.dimmed && !options.active ? "0.45" : "1",
      color: options.active ? ink : muted,
      "background-color": options.active ? accentSoft : "transparent",
      border: `1px solid ${options.active ? accent : line}`
    })
    chip.appendChild(
      makeText("span", options.label, { "font-size": "11px", color: "inherit" })
    )
    if (typeof options.count === "number") {
      chip.appendChild(
        makeText("span", String(options.count), {
          "font-size": "10px",
          "font-variant-numeric": "tabular-nums",
          color: options.active ? muted : faint
        })
      )
    }
    chip.addEventListener("click", (event) => {
      event.preventDefault()
      options.onClick()
    })
    return chip
  }

  /**
   * One control, several mutually exclusive segments. Used only for the choice
   * of library — indicator templates or hunting playbooks — so that it never
   * looks like the narrowing filters next to it.
   */
  const makeSegmented = (
    segments: {
      label: string
      count: number
      active: boolean
      title?: string
      onClick: () => void
    }[]
  ) => {
    const group = document.createElement("div")
    group.setAttribute("role", "tablist")
    group.setAttribute("aria-label", "Query library")
    setStyles(group, {
      all: "initial",
      display: "inline-flex",
      "align-items": "center",
      gap: "2px",
      padding: "2px",
      "border-radius": "999px",
      "background-color": fill,
      border: `1px solid ${line}`,
      "font-family": font
    })

    for (const segment of segments) {
      const button = document.createElement("button")
      button.type = "button"
      button.setAttribute("role", "tab")
      button.setAttribute("aria-selected", String(segment.active))
      if (segment.title) button.title = segment.title
      setStyles(button, {
        all: "initial",
        display: "inline-flex",
        "align-items": "center",
        gap: "6px",
        padding: "5px 12px",
        "border-radius": "999px",
        "font-family": font,
        "font-size": "11px",
        "font-weight": "700",
        "white-space": "nowrap",
        cursor: "pointer",
        color: segment.active ? "#111322" : muted,
        "background-color": segment.active ? accent : "transparent",
        border: "1px solid transparent"
      })
      button.appendChild(
        makeText("span", segment.label, {
          "font-size": "11px",
          "font-weight": "700",
          color: "inherit"
        })
      )
      button.appendChild(
        makeText("span", String(segment.count), {
          "font-size": "10px",
          "font-variant-numeric": "tabular-nums",
          color: "inherit",
          opacity: "0.7"
        })
      )
      button.addEventListener("click", (event) => {
        event.preventDefault()
        segment.onClick()
      })
      group.appendChild(button)
    }
    return group
  }

  const makeSelect = (options: {
    ariaLabel: string
    title?: string
    entries: { value: string; label: string; title?: string }[]
    value: string
    active: boolean
    onChange: (value: string) => void
  }) => {
    const select = document.createElement("select")
    select.setAttribute("aria-label", options.ariaLabel)
    if (options.title) select.title = options.title
    setStyles(select, {
      all: "initial",
      display: "inline-flex",
      "font-family": font,
      "font-size": "11px",
      "font-weight": "600",
      padding: "4px 8px",
      "border-radius": "999px",
      "max-width": "230px",
      cursor: "pointer",
      color: options.active ? ink : muted,
      "background-color": options.active ? accentSoft : "transparent",
      border: `1px solid ${options.active ? accent : line}`
    })
    for (const entry of options.entries) {
      const option = document.createElement("option")
      option.value = entry.value
      option.textContent = entry.label
      if (entry.title) option.title = entry.title
      // Native option lists are painted outside the panel, where the inherited
      // colours do not apply: set them so a dark console does not end up
      // drawing dark text on a dark drop-down.
      setStyles(option, {
        color: dark ? "#f4f7ff" : "#111322",
        "background-color": dark ? "#0d1524" : "#ffffff"
      })
      select.appendChild(option)
    }
    select.value = options.value
    select.addEventListener("change", () => options.onChange(select.value))
    return select
  }

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
      color: primary ? "#111322" : ink,
      "background-color": primary ? accent : "transparent",
      border: `1px solid ${primary ? accent : strongLine}`
    })
    return button
  }

  const makeStar = (starred: boolean, size: "row" | "title") => {
    const star = document.createElement("button")
    star.type = "button"
    star.textContent = starred ? "★" : "☆"
    star.title = starred ? "Remove from favorites" : "Add to favorites (Alt+F)"
    star.setAttribute(
      "aria-label",
      starred ? "Remove from favorites" : "Add to favorites"
    )
    star.setAttribute("aria-pressed", String(starred))
    setStyles(star, {
      all: "initial",
      display: "inline-flex",
      "align-items": "center",
      "justify-content": "center",
      width: size === "title" ? "26px" : "20px",
      height: size === "title" ? "26px" : "20px",
      "flex-shrink": "0",
      "border-radius": "999px",
      "font-family": font,
      "font-size": size === "title" ? "16px" : "13px",
      "line-height": "1",
      cursor: "pointer",
      color: starred ? accent : faint,
      "background-color": "transparent",
      border: "0"
    })
    return star
  }

  // ----------------------------------------------------------------- header
  const header = document.createElement("div")
  setStyles(header, {
    all: "initial",
    display: "flex",
    "flex-direction": "column",
    gap: embedded ? "8px" : "10px",
    padding: embedded ? "9px 12px" : "12px 14px 10px",
    "border-bottom": `1px solid ${line}`,
    "font-family": font
  })

  const titleRow = document.createElement("div")
  setStyles(titleRow, {
    all: "initial",
    display: embedded ? "none" : "flex",
    "align-items": "center",
    gap: "8px",
    "font-family": font
  })
  titleRow.append(
    makeText("span", "SOCx", {
      "font-size": "10px",
      "font-weight": "800",
      "letter-spacing": "0.28em",
      "text-transform": "uppercase",
      color: accent
    }),
    makeText("span", embedded ? "Query workspace" : "Query palette", {
      "font-size": "11px",
      "font-weight": "600",
      color: muted
    })
  )
  if (request.platformLabel) {
    titleRow.appendChild(makeBadge(request.platformLabel, "accent"))
  }

  const spacer = document.createElement("span")
  setStyles(spacer, { all: "initial", flex: "1 1 auto" })
  const counter = makeText("span", "", {
    "font-size": "11px",
    "font-variant-numeric": "tabular-nums",
    color: faint
  })
  titleRow.append(spacer, counter)
  if (!embedded) {
    const closeButton = document.createElement("button")
    closeButton.type = "button"
    closeButton.textContent = "×"
    closeButton.title = "Close query palette"
    closeButton.setAttribute("aria-label", "Close query palette")
    setStyles(closeButton, {
      all: "initial",
      display: "inline-flex",
      "align-items": "center",
      "justify-content": "center",
      width: "26px",
      height: "26px",
      "flex-shrink": "0",
      "border-radius": "999px",
      "font-family": font,
      "font-size": "20px",
      "line-height": "1",
      color: muted,
      cursor: "pointer",
      border: `1px solid ${line}`,
      "background-color": "transparent"
    })
    closeButton.addEventListener("click", () => closePalette())
    titleRow.appendChild(closeButton)
  }

  const searchRow = document.createElement("div")
  setStyles(searchRow, {
    all: "initial",
    display: "flex",
    "align-items": "center",
    gap: "8px",
    padding: "8px 10px",
    "border-radius": "12px",
    "background-color": fill,
    border: `1px solid ${line}`,
    "font-family": font
  })

  const search = document.createElement("input")
  search.type = "text"
  search.setAttribute("aria-label", "Search queries")
  search.title =
    "Search names, descriptions, query text, fields, commands, tags and ATT&CK identifiers"
  // Deep search: the placeholder has to say so, or nobody types a field name.
  search.placeholder = "Search a name, a description, a field or a value"
  setStyles(search, {
    all: "initial",
    flex: "1 1 auto",
    "font-family": font,
    "font-size": "14px",
    color: ink,
    "background-color": "transparent",
    border: "0",
    outline: "none",
    "min-width": "0"
  })
  searchRow.append(
    makeText("span", "⌕", {
      "font-size": "16px",
      "line-height": "1",
      color: faint
    }),
    search
  )

  // The library choice stays visible. Narrowing filters are collapsed until
  // needed, which gives the catalogue more vertical room in both surfaces.
  const scopeRow = document.createElement("div")
  setStyles(scopeRow, {
    all: "initial",
    display: "flex",
    "align-items": "center",
    "flex-wrap": "wrap",
    gap: "8px",
    "font-family": font
  })

  const filterRow = document.createElement("div")
  setStyles(filterRow, {
    all: "initial",
    display: "flex",
    "align-items": "center",
    "flex-wrap": "wrap",
    gap: "6px",
    padding: "8px 10px 10px",
    "border-top": `1px solid ${line}`,
    "font-family": font
  })

  const filterDetails = document.createElement("details")
  setStyles(filterDetails, {
    all: "initial",
    display: "block",
    "border-radius": "10px",
    border: `1px solid ${line}`,
    "font-family": font,
    overflow: "hidden"
  })
  const filterSummary = document.createElement("summary")
  filterSummary.title =
    "Filter by query language, category and repository-specific fields"
  setStyles(filterSummary, {
    all: "initial",
    display: "flex",
    "align-items": "center",
    "justify-content": "space-between",
    gap: "8px",
    padding: "7px 10px",
    "font-family": font,
    "font-size": "11px",
    "font-weight": "700",
    color: muted,
    cursor: "pointer"
  })
  const filterSummaryLabel = makeText("span", "More filters", {
    "font-size": "11px",
    "font-weight": "700",
    color: "inherit"
  })
  const filterSummaryMeta = makeText("span", "", {
    "font-size": "10px",
    "font-variant-numeric": "tabular-nums",
    color: faint
  })
  filterSummary.append(filterSummaryLabel, filterSummaryMeta)
  filterDetails.append(filterSummary, filterRow)
  filterDetails.addEventListener("toggle", () => {
    filterSummaryMeta.textContent = `${filtered.length} matches · ${
      filterDetails.open ? "Hide" : "Show"
    }`
  })

  header.append(titleRow, searchRow, scopeRow, filterDetails)

  // ------------------------------------------------------------------- body
  const body = document.createElement("div")
  setStyles(body, {
    all: "initial",
    display: "flex",
    flex: "1 1 auto",
    "min-height": "0",
    "font-family": font
  })

  const threePane = window.innerWidth >= (embedded ? 900 : 1100)

  const list = document.createElement("div")
  list.setAttribute("role", "listbox")
  list.setAttribute("aria-label", "Query results")
  setStyles(list, {
    all: "initial",
    display: "block",
    width: threePane ? "34%" : "42%",
    "min-width": threePane ? "280px" : "220px",
    "overflow-y": "auto",
    padding: "6px 0 10px",
    "border-right": `1px solid ${line}`,
    "font-family": font
  })

  // The right hand column: the indicator list on top, always visible and always
  // editable, and the template detail below it. The analyst must be able to see
  // — and correct — exactly what is going to be substituted into the query,
  // whether it came from the selection, from Bulk Check, or from their keyboard.
  const previewColumn = document.createElement("div")
  setStyles(previewColumn, {
    all: "initial",
    display: "flex",
    "flex-direction": "column",
    flex: "1 1 auto",
    "min-width": "0",
    "min-height": "0",
    "font-family": font
  })

  const indicatorBox = document.createElement("div")
  setStyles(indicatorBox, {
    all: "initial",
    display: "flex",
    "flex-direction": "column",
    gap: "6px",
    padding: "10px 16px",
    "border-bottom": `1px solid ${line}`,
    "font-family": font
  })

  const indicatorHeader = document.createElement("div")
  setStyles(indicatorHeader, {
    all: "initial",
    display: "flex",
    "align-items": "center",
    "flex-wrap": "wrap",
    gap: "8px",
    "font-family": font
  })
  const indicatorSummary = makeText("span", "", {
    display: "block",
    width: "100%",
    order: "2",
    "font-size": "11px",
    color: muted
  })
  const indicatorSpacer = document.createElement("span")
  setStyles(indicatorSpacer, { all: "initial", flex: "1 1 auto" })
  const mergeSlot = document.createElement("span")
  setStyles(mergeSlot, { all: "initial", display: "inline-flex" })
  indicatorHeader.append(
    makeText("span", "Indicators", {
      "font-size": "10px",
      "font-weight": "700",
      "letter-spacing": "0.12em",
      "text-transform": "uppercase",
      color: faint
    }),
    indicatorSpacer,
    mergeSlot,
    indicatorSummary
  )

  const indicators = document.createElement("textarea")
  indicators.rows = 3
  indicators.spellcheck = false
  indicators.setAttribute("aria-label", "Indicators used by the query")
  indicators.placeholder =
    "8.8.8.8, evil.example, hxxps://bad.test — paste or type, defanged is fine"
  indicators.value = (request.indicatorHint ?? []).join("\n")
  setStyles(indicators, {
    all: "initial",
    display: "block",
    width: "100%",
    "box-sizing": "border-box",
    resize: "vertical",
    "font-family": mono,
    "font-size": "12px",
    "line-height": "1.45",
    "max-height": "22vh",
    color: ink,
    "background-color": fill,
    border: `1px solid ${line}`,
    "border-radius": "10px",
    padding: "8px 10px",
    outline: "none"
  })

  indicatorBox.append(indicatorHeader, indicators)

  const preview = document.createElement("div")
  setStyles(preview, {
    all: "initial",
    display: "flex",
    "flex-direction": "column",
    flex: "1 1 auto",
    "min-width": "0",
    "min-height": "0",
    // The two children scroll on their own, so the query keeps its share of the
    // column however much metadata sits above it.
    overflow: "hidden",
    padding: "14px 16px",
    gap: "8px",
    "font-family": font
  })

  if (threePane) {
    setStyles(indicatorBox, {
      width: "24%",
      "min-width": "210px",
      "box-sizing": "border-box",
      "border-right": `1px solid ${line}`,
      "border-bottom": "0",
      padding: "14px"
    })
    setStyles(indicators, {
      flex: "1 1 auto",
      "min-height": "180px",
      "max-height": "none",
      resize: "none"
    })
    body.append(indicatorBox, list, preview)
  } else {
    previewColumn.append(indicatorBox, preview)
    body.append(list, previewColumn)
  }

  // ----------------------------------------------------------------- footer
  const footer = document.createElement("div")
  setStyles(footer, {
    all: "initial",
    display: "flex",
    "align-items": "center",
    "justify-content": "space-between",
    gap: "8px",
    padding: "10px 14px",
    "border-top": `1px solid ${line}`,
    "font-family": font
  })

  const hint = makeText(
    "span",
    embedded
      ? "Select a template, adjust its options, then copy the generated query"
      : "↑↓ move · ↵ insert · ⇧↵ at caret · Alt+F favorite · Esc close",
    { "font-size": "11px", color: faint }
  )

  const copyButton = makeButton("Copy")
  const insertButton = makeButton("Insert", true)
  const actions = document.createElement("div")
  setStyles(actions, { all: "initial", display: "flex", gap: "8px" })
  actions.append(copyButton)
  if (!embedded) actions.append(insertButton)
  footer.append(hint, actions)

  panel.append(header, body, footer)
  overlay.appendChild(panel)

  // ------------------------------------------------------------------ state
  let favorites = [...(request.favorites ?? [])]
  let mergeTypes = request.mergeTypes !== false
  let filters: PaletteFilterState = { ...ALL_FILTERS, labels: {} }
  let filtered = request.entries
  let favoriteCount = 0
  let activeIndex = 0
  let visibleLimit = PAGE_SIZE
  const variablesByEntry = new Map<string, Record<string, string>>()
  let rendered: { text: string; note?: string; warning?: string }[] = []

  const activeEntry = (): PaletteEntry | undefined => filtered[activeIndex]

  // Consumed once: the requested template wins over the favourites that would
  // otherwise sit at the top of the very first render.
  let pendingKey = request.initialKey
  const recompute = (options: { keepActive?: boolean } = {}) => {
    const previousKey = options.keepActive ? activeEntry()?.key : pendingKey
    pendingKey = undefined
    const outcome = applyPaletteFilters(request.entries, filters, favorites)
    filtered = outcome.entries
    favoriteCount = outcome.favoriteCount
    const restored = previousKey
      ? filtered.findIndex((entry) => entry.key === previousKey)
      : -1
    activeIndex = restored >= 0 ? restored : 0
    visibleLimit = Math.max(PAGE_SIZE, activeIndex + 1)
    renderFilters()
    renderList()
    renderPreview()
  }

  const setFilters = (patch: Partial<PaletteFilterState>) => {
    filters = { ...filters, ...patch }
    recompute()
  }

  const toggleFavorite = (key: string) => {
    if (!key) return
    favorites = toggleFavoriteKey(favorites, key)
    request.onToggleFavorite?.(key, favorites)
    recompute({ keepActive: true })
  }

  // -------------------------------------------------------------- filter bar
  //
  // Filter values never disappear or reorder. The containing disclosure may be
  // closed, but its active count makes the current state visible at a glance.
  function renderFilters() {
    scopeRow.textContent = ""
    filterRow.textContent = ""
    const facets = buildFacets(
      request.entries,
      filters,
      favorites,
      request.dialectLabels
    )
    const narrowFilterCount =
      Number(filters.dialect !== "all") +
      Number(filters.group !== "all") +
      Object.values(filters.labels ?? {}).filter((value) => value !== "all")
        .length
    filterSummaryLabel.textContent = narrowFilterCount
      ? `More filters · ${narrowFilterCount} active`
      : "More filters"
    filterSummaryMeta.textContent = `${filtered.length} matches · ${
      filterDetails.open ? "Hide" : "Show"
    }`

    // The two libraries are not one filter among many: they choose *what you
    // are browsing*, so they get a segmented control of their own.
    scopeRow.appendChild(
      makeSegmented([
        {
          label: "All queries",
          active: filters.kind === "all",
          count: facets.kinds.reduce((sum, option) => sum + option.count, 0),
          title: "Indicator templates and hunting playbooks together",
          onClick: () => setFilters({ kind: "all" })
        },
        ...facets.kinds.map((option) => ({
          label: option.label,
          count: option.count,
          active: filters.kind === option.value,
          title:
            option.value === "ioc"
              ? "Templates that hunt the indicators you selected"
              : "Hunting playbooks that need no indicator",
          onClick: () =>
            setFilters({ kind: option.value as PaletteFilterState["kind"] })
        }))
      ])
    )

    scopeRow.appendChild(
      makeChip({
        label: `★ ${FAVORITES_LABEL}`,
        count: facets.favorites,
        active: filters.favoritesOnly,
        title: "Show only the queries you starred",
        onClick: () => setFilters({ favoritesOnly: !filters.favoritesOnly })
      })
    )

    const scopeSpacer = document.createElement("span")
    setStyles(scopeSpacer, { all: "initial", flex: "1 1 auto" })
    scopeRow.appendChild(scopeSpacer)

    const clear = makeText("button", "Clear filters", {
      "font-size": "11px",
      "font-weight": "600",
      padding: "4px 8px",
      color: hasActiveFilters(filters) ? muted : faint,
      cursor: hasActiveFilters(filters) ? "pointer" : "default",
      opacity: hasActiveFilters(filters) ? "1" : "0.5",
      "background-color": "transparent",
      border: "0",
      "text-decoration": "underline"
    }) as HTMLButtonElement
    clear.type = "button"
    clear.title = "Reset search, query type and every narrowing filter"
    clear.disabled = !hasActiveFilters(filters)
    clear.addEventListener("click", () => {
      search.value = ""
      filters = { ...ALL_FILTERS, labels: {} }
      recompute()
      search.focus()
    })
    scopeRow.appendChild(clear)

    if (facets.dialects.length <= MAX_DIALECT_CHIPS) {
      for (const option of facets.dialects) {
        const active = filters.dialect === option.value
        filterRow.appendChild(
          makeChip({
            label: option.label,
            count: option.count,
            active,
            dimmed: option.count === 0,
            title: option.title ?? option.label,
            onClick: () =>
              setFilters({ dialect: active ? "all" : option.value })
          })
        )
      }
    } else {
      filterRow.appendChild(
        makeSelect({
          ariaLabel: "Filter by query language",
          title: "Show templates written for one query language or product",
          active: filters.dialect !== "all",
          value: filters.dialect,
          entries: [
            { value: "all", label: "Language: all" },
            ...facets.dialects.map((option) => ({
              value: option.value,
              label: `${option.label} (${option.count})`,
              title: option.title
            }))
          ],
          onChange: (value) => setFilters({ dialect: value })
        })
      )
    }

    filterRow.appendChild(
      makeSelect({
        ariaLabel: "Filter by category",
        title: "Narrow templates to one catalogue category",
        active: filters.group !== "all",
        value: filters.group,
        entries: [
          { value: "all", label: "Category: all" },
          ...facets.groups.map((option) => ({
            value: option.value,
            label: `${option.label} (${option.count})`
          }))
        ],
        onChange: (value) => setFilters({ group: value })
      })
    )

    // Whatever dimensions the repository declared for itself: customers,
    // tenants, squads. They sit last so the built-in filters keep their place.
    for (const facet of facets.custom) {
      filterRow.appendChild(
        makeSelect({
          ariaLabel: `Filter by ${facet.label}`,
          title: facet.description || `Narrow templates by ${facet.label}`,
          active: (filters.labels?.[facet.id] ?? "all") !== "all",
          value: filters.labels?.[facet.id] ?? "all",
          entries: [
            { value: "all", label: `${facet.label}: all` },
            ...facet.options.map((option) => ({
              value: option.value,
              label: `${option.label} (${option.count})`,
              title: facet.description
            }))
          ],
          onChange: (value) =>
            setFilters({ labels: { ...filters.labels, [facet.id]: value } })
        })
      )
    }
  }

  // ----------------------------------------------------------------- preview
  function renderPreview() {
    preview.textContent = ""
    const entry = activeEntry()
    if (!entry) {
      rendered = []
      indicatorBox.style.setProperty(
        "display",
        threePane ? "flex" : "none",
        "important"
      )
      indicatorBox.style.setProperty("opacity", "0.5", "important")
      indicatorSummary.textContent = "No selected query"
      preview.append(
        makeText(
          "p",
          filters.favoritesOnly && favorites.length === 0
            ? "No favorite yet."
            : "No query matches these filters.",
          { "font-size": "13px", "font-weight": "600", color: ink }
        ),
        makeText(
          "p",
          filters.favoritesOnly
            ? "Star a query with Alt+F, or with the ☆ next to its name, to build your shortlist."
            : "Try a shorter search, another language, or clear the filters.",
          { "font-size": "12px", "line-height": "1.5", color: muted }
        )
      )
      return
    }

    // In the three-pane view the indicator column stays put so selecting a
    // hunting playbook does not make the layout jump. Compact overlays can
    // still hide it to protect the query preview.
    indicatorBox.style.setProperty(
      "display",
      entry.template.requiresIocs || threePane ? "flex" : "none",
      "important"
    )
    indicatorBox.style.setProperty(
      "opacity",
      entry.template.requiresIocs ? "1" : "0.5",
      "important"
    )
    indicatorSummary.textContent = entry.template.requiresIocs
      ? (request.describeIndicators?.(indicators.value) ?? "")
      : "Not used by this hunting query"

    const variables = variablesByEntry.get(entry.key) ?? {}
    variablesByEntry.set(entry.key, variables)

    // Everything that describes the query goes in the top box, which takes at
    // most half the column and scrolls; the query itself owns the rest. A
    // template with a long description and a handful of variables used to push
    // its own output out of sight.
    const meta = document.createElement("div")
    setStyles(meta, {
      all: "initial",
      display: "flex",
      "flex-direction": "column",
      gap: "8px",
      flex: "0 1 auto",
      "min-height": "0",
      "max-height": "45%",
      "overflow-y": "auto",
      "font-family": font
    })
    const queryBox = document.createElement("div")
    setStyles(queryBox, {
      all: "initial",
      display: "flex",
      "flex-direction": "column",
      gap: "8px",
      flex: "1 1 auto",
      // The floor is what actually guarantees the query is on screen: the meta
      // box above is allowed to shrink, so the percentage cap is only there to
      // keep the split comfortable when the column is tall.
      "min-height": "120px",
      "overflow-y": "auto",
      "font-family": font
    })
    preview.append(meta, queryBox)

    const titleLine = document.createElement("div")
    setStyles(titleLine, {
      all: "initial",
      display: "flex",
      "align-items": "center",
      gap: "8px",
      "font-family": font
    })
    const star = makeStar(favorites.includes(entry.key), "title")
    star.addEventListener("click", (event) => {
      event.preventDefault()
      toggleFavorite(entry.key)
    })
    titleLine.append(
      makeText("p", entry.template.name, {
        "font-size": "15px",
        "font-weight": "700",
        flex: "1 1 auto",
        color: ink
      }),
      star
    )
    meta.appendChild(titleLine)

    const badges = document.createElement("div")
    setStyles(badges, {
      all: "initial",
      display: "flex",
      "flex-wrap": "wrap",
      "align-items": "center",
      gap: "6px",
      "font-family": font
    })
    badges.append(
      makeBadge(KIND_LABELS[entry.pack.kind] ?? entry.pack.kind, "neutral"),
      makeBadge(dialectChipLabel(entryDialect(entry)), "neutral")
    )
    badges.appendChild(
      makeBadge(
        entry.pack.verified === true ? "verified pack" : "unverified fields",
        entry.pack.verified === true ? "accent" : "warn"
      )
    )
    for (const values of Object.values(resolveEntryLabels(entry))) {
      for (const value of values)
        badges.appendChild(makeBadge(value, "neutral"))
    }
    const tags = entry.template.tags ?? []
    for (const tag of tags.slice(0, 4)) {
      badges.appendChild(makeBadge(tag, "neutral"))
    }
    if (tags.length > 4) {
      const rest = tags.slice(4)
      const more = makeBadge(`+${rest.length}`, "neutral")
      more.title = rest.join(", ")
      badges.appendChild(more)
    }
    meta.appendChild(badges)

    meta.appendChild(
      makeText("p", `${entry.path.join(" › ")} · ${entry.pack.name}`, {
        "font-size": "11px",
        color: muted
      })
    )

    if (entry.template.description) {
      meta.appendChild(
        makeText("p", entry.template.description, {
          "font-size": "12px",
          "line-height": "1.5",
          color: dark ? "rgba(244,247,255,0.82)" : "rgba(17,19,34,0.78)"
        })
      )
    }

    const references = document.createElement("div")
    setStyles(references, {
      all: "initial",
      display: "flex",
      "flex-wrap": "wrap",
      gap: "6px",
      "font-family": font
    })
    if (/^https?:\/\//i.test(entry.template.reference ?? "")) {
      const reference = makeText("a", "Template reference ↗", {
        "font-size": "11px",
        "font-weight": "600",
        color: muted,
        "text-decoration": "underline"
      }) as HTMLAnchorElement
      reference.href = entry.template.reference
      reference.target = "_blank"
      reference.rel = "noreferrer"
      references.appendChild(reference)
    }
    for (const technique of entry.template.mitre ?? []) {
      references.appendChild(makeBadge(technique, "neutral"))
    }
    if (references.childElementCount > 0) meta.appendChild(references)

    // Variable inputs, which are the only input a standard query needs. Only
    // the ones this template actually substitutes are offered: a pack declares
    // its variables once for every template in it, and a field the query never
    // reads does nothing when it is filled in.
    const variableFields = templateVariables(entry.pack, entry.template)
    const variableGrid = document.createElement("div")
    setStyles(variableGrid, {
      all: "initial",
      display: "grid",
      "grid-template-columns": "repeat(auto-fit, minmax(210px, 1fr))",
      gap: "6px 10px",
      "font-family": font
    })
    if (variableFields.length > 0) meta.appendChild(variableGrid)

    for (const variable of variableFields) {
      const row = document.createElement("label")
      row.title =
        variable.description ||
        `${variable.label} changes the value inserted into the generated query.`
      setStyles(row, {
        all: "initial",
        display: "flex",
        "align-items": "center",
        gap: "8px",
        "min-width": "0",
        "font-family": font,
        "font-size": "12px",
        color: ink
      })
      const label = makeText("span", variable.label, {
        "font-size": "12px",
        "min-width": "0",
        "max-width": "45%",
        "white-space": "nowrap",
        overflow: "hidden",
        "text-overflow": "ellipsis",
        color: muted
      })

      const input = variable.options?.length
        ? document.createElement("select")
        : document.createElement("input")
      input.setAttribute("aria-label", variable.label)
      if (variable.type === "checkbox" && input instanceof HTMLInputElement) {
        input.type = "checkbox"
        input.setAttribute("role", "switch")
        setStyles(input, {
          all: "initial",
          appearance: "none",
          width: "34px",
          height: "20px",
          flex: "0 0 auto",
          cursor: "pointer",
          "border-radius": "999px",
          border: `1px solid ${line}`,
          outline: "none"
        })
      } else {
        setStyles(input, {
          all: "initial",
          "font-family": font,
          "font-size": "12px",
          color: ink,
          "background-color": fill,
          border: `1px solid ${line}`,
          "border-radius": "8px",
          padding: "5px 8px",
          flex: "1 1 auto",
          "min-width": "0"
        })
      }

      const current = variables[variable.id] ?? variable.default ?? ""
      if (input instanceof HTMLSelectElement) {
        for (const option of variable.options ?? []) {
          const element = document.createElement("option")
          element.value = option
          element.textContent = option
          setStyles(element, {
            color: dark ? "#f4f7ff" : "#111322",
            "background-color": dark ? "#0d1524" : "#ffffff"
          })
          input.appendChild(element)
        }
        input.value = current
      } else if (input.type === "checkbox") {
        input.checked = current === "true"
        const thumbPosition = input.checked ? "24px" : "9px"
        setStyles(input, {
          "background-color": input.checked ? accentSoft : fill,
          "background-image": `radial-gradient(circle at ${thumbPosition} 50%, ${
            input.checked ? accent : faint
          } 0 6px, transparent 6.5px)`
        })
      } else {
        ;(input as HTMLInputElement).value = current
      }

      const updateVariable = () => {
        variables[variable.id] =
          input instanceof HTMLInputElement && input.type === "checkbox"
            ? String(input.checked)
            : input.value
        renderPreview()
      }
      input.addEventListener("input", updateVariable)
      input.addEventListener("change", updateVariable)

      row.append(label, input)
      variableGrid.appendChild(row)
    }

    rendered = request.onRender(entry, {
      variables,
      indicatorText: indicators.value,
      mergeTypes
    })

    if (rendered.length === 0) {
      queryBox.appendChild(
        makeText(
          "p",
          "This template needs indicators of a type the current selection does not contain.",
          { "font-size": "12px", "line-height": "1.5", color: warn }
        )
      )
      return
    }

    rendered.forEach((query) => {
      if (query.warning) {
        queryBox.appendChild(
          makeText("p", query.warning, { "font-size": "11px", color: warn })
        )
      }
      if (query.note) {
        queryBox.appendChild(
          makeText("p", query.note, { "font-size": "11px", color: faint })
        )
      }
      queryBox.appendChild(
        makeText("pre", query.text, {
          display: "block",
          "font-family": mono,
          "font-size": "12px",
          "line-height": "1.5",
          "white-space": "pre-wrap",
          "word-break": "break-word",
          padding: "10px 12px",
          "border-radius": "12px",
          color: ink,
          border: `1px solid ${line}`,
          "background-color": fill
        })
      )
    })
  }

  // -------------------------------------------------------------------- list
  const makeSectionHeading = (label: string, starred: boolean) =>
    makeText("p", label, {
      display: "block",
      padding: "10px 14px 4px",
      "font-size": "10px",
      "font-weight": "700",
      "letter-spacing": "0.12em",
      "text-transform": "uppercase",
      color: starred ? accent : faint
    })

  function renderList() {
    list.textContent = ""
    counter.textContent = `${filtered.length} of ${request.entries.length}`

    if (filtered.length === 0) {
      list.appendChild(
        makeText("p", "Nothing to show", {
          display: "block",
          padding: "16px 14px",
          "font-size": "12px",
          color: muted
        })
      )
      return
    }

    const visible = Math.min(filtered.length, visibleLimit)
    let lastSection = ""
    for (let index = 0; index < visible; index += 1) {
      const entry = filtered[index]
      const starred = index < favoriteCount
      const section = starred ? `★ ${FAVORITES_LABEL}` : entry.path.join(" › ")
      if (section !== lastSection) {
        lastSection = section
        list.appendChild(makeSectionHeading(section, starred))
      }

      const item = document.createElement("div")
      item.setAttribute("role", "option")
      item.setAttribute("aria-selected", String(index === activeIndex))
      item.setAttribute("data-index", String(index))
      setStyles(item, {
        all: "initial",
        display: "flex",
        "align-items": "center",
        gap: "6px",
        margin: "1px 6px",
        padding: "6px 8px",
        "border-radius": "9px",
        "font-family": font,
        "font-size": "13px",
        cursor: "pointer",
        color: ink,
        "background-color": index === activeIndex ? accentSoft : "transparent",
        "box-shadow":
          index === activeIndex ? `inset 2px 0 0 0 ${accent}` : "none"
      })

      const isFavorite = favorites.includes(entry.key)
      const star = makeStar(isFavorite, "row")
      // An empty star on every row would be visual noise; it appears on the
      // row the analyst is actually pointing at or moving through.
      if (!isFavorite && index !== activeIndex) {
        star.style.setProperty("opacity", "0", "important")
      }
      item.addEventListener("mouseenter", () => {
        star.style.setProperty("opacity", "1", "important")
        if (index !== activeIndex) {
          item.style.setProperty("background-color", fill, "important")
        }
      })
      item.addEventListener("mouseleave", () => {
        if (!favorites.includes(entry.key) && index !== activeIndex) {
          star.style.setProperty("opacity", "0", "important")
        }
        if (index !== activeIndex) {
          item.style.setProperty("background-color", "transparent", "important")
        }
      })
      star.addEventListener("click", (event) => {
        event.preventDefault()
        event.stopPropagation()
        toggleFavorite(entry.key)
      })

      // Name on top, and the template's own description below it: two lines are
      // what makes a list of near-identical query names actually pickable.
      const text = document.createElement("div")
      setStyles(text, {
        all: "initial",
        display: "flex",
        "flex-direction": "column",
        gap: "1px",
        flex: "1 1 auto",
        "min-width": "0",
        "font-family": font,
        // `all: initial` resets the colour to black, so the name has to be
        // repainted here rather than inherited from the row.
        color: ink
      })
      const truncate: Record<string, string> = {
        display: "block",
        overflow: "hidden",
        "text-overflow": "ellipsis",
        "white-space": "nowrap"
      }
      text.appendChild(
        makeText("span", entry.template.name, {
          ...truncate,
          "font-size": "13px",
          color: "inherit"
        })
      )
      const subtitle =
        entry.template.description?.trim() ||
        Object.values(resolveEntryLabels(entry)).flat().join(" · ")
      if (subtitle) {
        text.appendChild(
          makeText("span", subtitle, {
            ...truncate,
            "font-size": "11px",
            "line-height": "1.35",
            color: muted
          })
        )
      }

      item.append(text, star)
      item.addEventListener("click", () => {
        activeIndex = index
        request.onSelectedKeyChange?.(entry.key)
        renderList()
        renderPreview()
      })
      if (!embedded) {
        item.addEventListener("dblclick", () => void insert("replace"))
      }
      list.appendChild(item)
    }

    if (filtered.length > visible) {
      const more = makeText(
        "button",
        `Show ${filtered.length - visible} more`,
        {
          display: "block",
          width: "calc(100% - 12px)",
          margin: "8px 6px 0",
          padding: "7px 8px",
          "border-radius": "9px",
          "font-size": "11px",
          "font-weight": "600",
          cursor: "pointer",
          color: muted,
          "background-color": "transparent",
          border: `1px dashed ${strongLine}`
        }
      ) as HTMLButtonElement
      more.type = "button"
      more.addEventListener("click", () => {
        visibleLimit += PAGE_SIZE * 2
        renderList()
      })
      list.appendChild(more)
    }

    const active = list.querySelector(`[data-index="${activeIndex}"]`)
    active?.scrollIntoView({ block: "nearest" })
  }

  // ----------------------------------------------------------------- actions
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
      if (!embedded) closePalette()
      showToast("Query copied to clipboard", "success")
    } catch {
      showToast("Could not copy the query", "danger")
    }
  }

  const move = (delta: number) => {
    if (filtered.length === 0) return
    activeIndex = Math.min(
      Math.max(activeIndex + delta, 0),
      filtered.length - 1
    )
    const entry = activeEntry()
    if (entry) request.onSelectedKeyChange?.(entry.key)
    // Walking past the fold expands it rather than trapping the cursor.
    if (activeIndex >= visibleLimit) {
      visibleLimit = Math.min(filtered.length, activeIndex + PAGE_SIZE)
    }
    renderList()
    renderPreview()
  }

  insertButton.addEventListener("click", () => void insert("replace"))
  copyButton.addEventListener("click", () => void copy())

  search.addEventListener("input", () => setFilters({ search: search.value }))

  const renderIndicatorSummary = () => {
    const selected = activeEntry()
    indicatorSummary.textContent =
      selected && !selected.template.requiresIocs
        ? "Not used by this hunting query"
        : (request.describeIndicators?.(indicators.value) ?? "")

    // One query for the whole selection, or one per indicator type. The choice
    // lives next to the list it applies to, and is remembered.
    mergeSlot.textContent = ""
    mergeSlot.appendChild(
      makeChip({
        label: mergeTypes ? "Single query" : "One per type",
        active: mergeTypes,
        title: mergeTypes
          ? "Every indicator type is compared in one query, each against its own field"
          : "Each indicator type gets its own query",
        onClick: () => {
          mergeTypes = !mergeTypes
          request.onMergeTypesChange?.(mergeTypes)
          renderIndicatorSummary()
          renderPreview()
        }
      })
    )
  }
  indicators.addEventListener("input", () => {
    request.onIndicatorTextChange?.(indicators.value)
    renderIndicatorSummary()
    renderPreview()
  })

  const onKeyDown = (event: KeyboardEvent) => {
    if (embedded) return
    if (event.key === "Escape") {
      event.preventDefault()
      event.stopPropagation()
      cleanup()
      return
    }
    // The palette listens in the capture phase, which is what lets it win over
    // the host page — so the indicator field has to be exempted here rather
    // than by stopping propagation from the field itself: inside it, Enter adds
    // a line and the arrows move the caret.
    if (event.target === indicators) return
    if (event.altKey && (event.key === "f" || event.key === "F")) {
      event.preventDefault()
      const entry = activeEntry()
      if (entry) toggleFavorite(entry.key)
      return
    }
    if (event.key === "ArrowDown" || (event.key === "n" && event.ctrlKey)) {
      event.preventDefault()
      move(1)
      return
    }
    if (event.key === "ArrowUp" || (event.key === "p" && event.ctrlKey)) {
      event.preventDefault()
      move(-1)
      return
    }
    if (event.key === "Enter") {
      event.preventDefault()
      void insert(event.shiftKey ? "caret" : "replace")
    }
  }

  const cleanup = () => {
    if (!embedded) document.removeEventListener("keydown", onKeyDown, true)
    overlay.remove()
    if (activePaletteCleanup === cleanup) {
      activePaletteCleanup = null
    }
  }

  if (!embedded) {
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) cleanup()
    })
    document.addEventListener("keydown", onKeyDown, true)
    activePaletteCleanup = cleanup
  }

  options.host.appendChild(overlay)
  renderIndicatorSummary()
  recompute()
  if (!embedded) search.focus()
  return cleanup
}

export const openPalette = (request: PaletteRequest): void => {
  if (typeof document === "undefined" || !document.documentElement) return
  closePalette()
  mountQueryView(request, {
    mode: "overlay",
    host: document.body ?? document.documentElement
  })
}
