import {
  filterQueryLanguageGuides,
  QUERY_LANGUAGE_GUIDES,
  type QueryLanguageGuide
} from "./guides"
import type { QueryDialect } from "./packSchema"

export type LanguageGuideTheme = {
  ink: string
  muted: string
  faint: string
  line: string
  strongLine: string
  scrollThumb: string
  fill: string
  surface: string
  control: string
  accent: string
  accentSoft: string
  warn: string
  font: string
  mono: string
  scrollClass: string
  dark: boolean
}

type LanguageGuideViewOptions = {
  dialects?: Map<string, QueryDialect>
  theme: LanguageGuideTheme
  /**
   * Overlay guides scroll inside the dialog; workspace guides grow with the
   * page.
   */
  constrained?: boolean
}

type LanguageGuideView = {
  element: HTMLDetailsElement
  syncDialect: (dialectId: string) => void
}

const setStyles = (
  element: HTMLElement,
  styles: Record<string, string>
): void => {
  for (const [property, value] of Object.entries(styles)) {
    element.style.setProperty(property, value, "important")
  }
}

export const createLanguageGuideView = (
  options: LanguageGuideViewOptions
): LanguageGuideView => {
  const { dialects, theme } = options
  const constrained = options.constrained !== false
  const {
    ink,
    muted,
    faint,
    line,
    strongLine,
    scrollThumb,
    fill,
    surface,
    control,
    accent,
    accentSoft,
    warn,
    font,
    mono,
    scrollClass,
    dark
  } = theme

  const text = (
    tag: keyof HTMLElementTagNameMap,
    value: string,
    styles: Record<string, string> = {}
  ): HTMLElement => {
    const element = document.createElement(tag)
    element.textContent = value
    setStyles(element, { all: "initial", "font-family": font, ...styles })
    return element
  }

  const productLabel = (dialectId: string): string => {
    const vendors = dialects?.get(dialectId)?.vendors ?? []
    return vendors.length > 0 ? vendors.join(" · ") : "Generic target"
  }

  const orderedGuides = [...QUERY_LANGUAGE_GUIDES].sort((a, b) =>
    (dialects?.get(a.dialectId)?.label ?? a.dialectId).localeCompare(
      dialects?.get(b.dialectId)?.label ?? b.dialectId
    )
  )

  const element = document.createElement("details")
  element.setAttribute("data-socx-language-guide", "true")
  setStyles(element, {
    all: "initial",
    position: constrained ? "relative" : "static",
    display: "block",
    flex: "0 0 auto",
    "max-width": "100%",
    "box-sizing": "border-box",
    border: `1px solid ${line}`,
    "border-radius": "16px",
    "background-color": surface,
    "font-family": font,
    overflow: "hidden"
  })

  const summary = document.createElement("summary")
  summary.title = "Open commands, main fields and official documentation"
  setStyles(summary, {
    all: "initial",
    display: "flex",
    "align-items": "center",
    "justify-content": "space-between",
    gap: "12px",
    padding: "9px 12px",
    "font-family": font,
    cursor: "pointer",
    color: ink
  })
  const summaryText = document.createElement("span")
  setStyles(summaryText, {
    all: "initial",
    display: "flex",
    "align-items": "baseline",
    "flex-wrap": "wrap",
    gap: "6px",
    "font-family": font,
    color: ink
  })
  summaryText.append(
    text("strong", "Query language mini guide", {
      "font-size": "12px",
      "font-weight": "700",
      color: ink
    }),
    text(
      "span",
      `${QUERY_LANGUAGE_GUIDES.length} languages · fields, commands and examples`,
      { "font-size": "10px", color: faint }
    )
  )
  const guideState = text("span", "Open", {
    "font-size": "10px",
    "font-weight": "700",
    color: muted
  })
  summary.append(summaryText, guideState)

  const content = document.createElement("div")
  content.setAttribute("data-socx-language-guide-content", "true")
  content.classList.add(scrollClass)
  setStyles(content, {
    all: "initial",
    display: "flex",
    "flex-direction": "column",
    gap: "10px",
    "max-height": constrained ? "min(52vh, 560px)" : "none",
    "max-width": "100%",
    "box-sizing": "border-box",
    padding: "12px",
    "border-top": `1px solid ${line}`,
    "font-family": font,
    "overflow-y": constrained ? "auto" : "visible",
    "overflow-x": "hidden",
    "scrollbar-width": "thin",
    "scrollbar-color": `${scrollThumb} transparent`
  })

  const controls = document.createElement("div")
  setStyles(controls, {
    all: "initial",
    display: "grid",
    "grid-template-columns": "minmax(0, 0.9fr) minmax(0, 1.1fr)",
    gap: "8px",
    "max-width": "100%",
    "font-family": font
  })

  const makeControl = (label: string, control: HTMLElement) => {
    const wrapper = document.createElement("label")
    setStyles(wrapper, {
      all: "initial",
      display: "flex",
      "flex-direction": "column",
      gap: "4px",
      "min-width": "0",
      "font-family": font
    })
    wrapper.append(
      text("span", label, {
        "font-size": "10px",
        "font-weight": "700",
        color: muted
      }),
      control
    )
    return wrapper
  }

  const controlStyles: Record<string, string> = {
    all: "initial",
    display: "block",
    width: "100%",
    "min-width": "0",
    "box-sizing": "border-box",
    padding: "7px 9px",
    "border-radius": "12px",
    "font-family": font,
    "font-size": "11px",
    color: ink,
    "background-color": control,
    border: `1px solid ${line}`,
    outline: "none"
  }

  const dialectSelect = document.createElement("select")
  dialectSelect.setAttribute(
    "aria-label",
    "Filter guide by language and product"
  )
  setStyles(dialectSelect, controlStyles)
  const allOption = document.createElement("option")
  allOption.value = "all"
  allOption.textContent = "All languages and products"
  dialectSelect.appendChild(allOption)
  for (const guide of orderedGuides) {
    const option = document.createElement("option")
    option.value = guide.dialectId
    option.textContent = `${dialects?.get(guide.dialectId)?.label ?? guide.dialectId} — ${productLabel(guide.dialectId)}`
    setStyles(option, {
      color: ink,
      "background-color": dark ? "#0d1524" : "#ffffff"
    })
    dialectSelect.appendChild(option)
  }

  const search = document.createElement("input")
  search.type = "search"
  search.placeholder = "Find a command, field, option or example"
  search.setAttribute("aria-label", "Search query language guides")
  setStyles(search, controlStyles)

  controls.append(
    makeControl("Language and product", dialectSelect),
    makeControl("Command, operator or field", search)
  )

  const resultCount = text("p", "", {
    "font-size": "10px",
    color: faint
  })
  const cards = document.createElement("div")
  setStyles(cards, {
    all: "initial",
    display: "grid",
    "grid-template-columns": "repeat(auto-fit, minmax(min(100%, 360px), 1fr))",
    gap: "10px",
    "max-width": "100%",
    "font-family": font
  })

  const code = (value: string, light = false): HTMLElement =>
    text("code", value, {
      display: "block",
      width: "100%",
      "max-width": "100%",
      "box-sizing": "border-box",
      padding: "7px 8px",
      "border-radius": "7px",
      "font-family": mono,
      "font-size": "10px",
      "line-height": "1.45",
      "white-space": "pre-wrap",
      "word-break": "break-word",
      "overflow-wrap": "anywhere",
      color: light ? ink : "#f4f7ff",
      "background-color": light
        ? dark
          ? "rgba(255,255,255,0.04)"
          : "rgba(17,19,34,0.04)"
        : "#0b1220",
      border: `1px solid ${line}`
    })

  const makeGuideCard = (
    guide: QueryLanguageGuide,
    open: boolean
  ): HTMLDetailsElement => {
    const card = document.createElement("details")
    card.open = open
    setStyles(card, {
      all: "initial",
      display: "block",
      "min-width": "0",
      "max-width": "100%",
      "box-sizing": "border-box",
      "border-radius": "16px",
      border: `1px solid ${line}`,
      "background-color": control,
      "font-family": font,
      overflow: "hidden"
    })
    const cardSummary = document.createElement("summary")
    setStyles(cardSummary, {
      all: "initial",
      display: "flex",
      "align-items": "flex-start",
      "justify-content": "space-between",
      gap: "8px",
      padding: "10px 11px",
      "font-family": font,
      cursor: "pointer",
      color: ink
    })
    const heading = document.createElement("span")
    setStyles(heading, {
      all: "initial",
      display: "flex",
      "flex-direction": "column",
      gap: "3px",
      "min-width": "0",
      "font-family": font
    })
    const nameLine = document.createElement("span")
    setStyles(nameLine, {
      all: "initial",
      display: "flex",
      "align-items": "center",
      "flex-wrap": "wrap",
      gap: "6px",
      "font-family": font
    })
    nameLine.append(
      text("span", guide.dialectId.toUpperCase(), {
        padding: "2px 7px",
        "border-radius": "999px",
        "font-family": mono,
        "font-size": "9px",
        "font-weight": "700",
        color: ink,
        "background-color": accentSoft
      }),
      text("strong", dialects?.get(guide.dialectId)?.label ?? guide.dialectId, {
        "font-size": "12px",
        "font-weight": "700",
        color: ink
      })
    )
    heading.append(
      nameLine,
      text("span", productLabel(guide.dialectId), {
        "font-size": "10px",
        color: faint
      })
    )
    cardSummary.append(
      heading,
      text("span", `${guide.commands.length} commands`, {
        "font-size": "9px",
        "font-weight": "700",
        color: muted
      })
    )

    const cardBody = document.createElement("div")
    setStyles(cardBody, {
      all: "initial",
      display: "flex",
      "flex-direction": "column",
      gap: "12px",
      padding: "11px",
      "border-top": `1px solid ${line}`,
      "font-family": font,
      color: ink
    })
    cardBody.appendChild(
      text("p", guide.summary, {
        "font-size": "11px",
        "line-height": "1.5",
        color: ink
      })
    )

    const detailGrid = document.createElement("div")
    setStyles(detailGrid, {
      all: "initial",
      display: "grid",
      "grid-template-columns":
        "repeat(auto-fit, minmax(min(100%, 260px), 1fr))",
      gap: "12px",
      "font-family": font
    })

    const fields = document.createElement("div")
    setStyles(fields, {
      all: "initial",
      display: "flex",
      "flex-direction": "column",
      gap: "6px",
      "min-width": "0",
      "font-family": font
    })
    fields.appendChild(
      text("h4", "Main fields", {
        "font-size": "11px",
        "font-weight": "700",
        color: ink
      })
    )
    for (const field of guide.fields) {
      const fieldCard = document.createElement("div")
      setStyles(fieldCard, {
        all: "initial",
        display: "flex",
        "flex-direction": "column",
        gap: "3px",
        padding: "8px",
        "border-radius": "12px",
        border: `1px solid ${line}`,
        "background-color": fill,
        "font-family": font
      })
      fieldCard.append(
        text("strong", field.term, {
          "font-family": mono,
          "font-size": "10px",
          "font-weight": "700",
          color: ink
        }),
        text("span", field.description, {
          "font-size": "10px",
          "line-height": "1.45",
          color: muted
        })
      )
      for (const note of field.notes ?? []) {
        fieldCard.appendChild(
          text("span", `• ${note}`, {
            "font-size": "10px",
            "line-height": "1.4",
            color: muted
          })
        )
      }
      if (field.example) fieldCard.appendChild(code(field.example))
      fields.appendChild(fieldCard)
    }

    const commands = document.createElement("div")
    setStyles(commands, {
      all: "initial",
      display: "flex",
      "flex-direction": "column",
      gap: "6px",
      "min-width": "0",
      "font-family": font
    })
    commands.append(
      text("h4", "Commands and operators", {
        "font-size": "11px",
        "font-weight": "700",
        color: ink
      }),
      text("p", "Select a command for syntax, options and an example.", {
        "font-size": "10px",
        color: faint
      })
    )
    for (const command of guide.commands) {
      const commandCard = document.createElement("details")
      setStyles(commandCard, {
        all: "initial",
        display: "block",
        "border-radius": "12px",
        border: `1px solid ${line}`,
        "background-color": fill,
        "font-family": font,
        overflow: "hidden"
      })
      const commandSummary = document.createElement("summary")
      setStyles(commandSummary, {
        all: "initial",
        display: "flex",
        "flex-direction": "column",
        gap: "2px",
        padding: "8px",
        "font-family": font,
        cursor: "pointer"
      })
      commandSummary.append(
        text("strong", command.term, {
          "font-family": mono,
          "font-size": "10px",
          "font-weight": "700",
          color: ink
        }),
        text("span", command.description, {
          "font-size": "10px",
          "line-height": "1.4",
          color: muted
        })
      )
      const commandBody = document.createElement("div")
      setStyles(commandBody, {
        all: "initial",
        display: "flex",
        "flex-direction": "column",
        gap: "7px",
        padding: "8px",
        "border-top": `1px solid ${line}`,
        "font-family": font
      })
      commandBody.append(
        text("strong", "Syntax", {
          "font-size": "9px",
          "font-weight": "700",
          color: faint,
          "text-transform": "uppercase"
        }),
        code(command.syntax),
        text("strong", "Main options", {
          "font-size": "9px",
          "font-weight": "700",
          color: faint,
          "text-transform": "uppercase"
        })
      )
      for (const option of command.options) {
        commandBody.appendChild(
          text("span", `• ${option}`, {
            "font-size": "10px",
            "line-height": "1.4",
            color: muted
          })
        )
      }
      commandBody.append(
        text("strong", "Short example", {
          "font-size": "9px",
          "font-weight": "700",
          color: faint,
          "text-transform": "uppercase"
        }),
        code(command.example, true)
      )
      commandCard.append(commandSummary, commandBody)
      commands.appendChild(commandCard)
    }

    detailGrid.append(fields, commands)
    cardBody.appendChild(detailGrid)
    if (guide.caution) {
      cardBody.appendChild(
        text("p", guide.caution, {
          padding: "8px",
          "border-radius": "8px",
          "font-size": "10px",
          "line-height": "1.45",
          color: warn,
          "background-color": "rgba(245,158,11,0.10)",
          border: `1px solid rgba(245,158,11,0.28)`
        })
      )
    }
    const documentation = text("a", `${guide.documentationLabel} ↗`, {
      "font-size": "10px",
      "font-weight": "700",
      color: muted,
      "text-decoration": "underline",
      "text-decoration-color": accent
    }) as HTMLAnchorElement
    documentation.href = guide.documentationUrl
    documentation.target = "_blank"
    documentation.rel = "noreferrer"
    documentation.setAttribute(
      "aria-label",
      `${guide.documentationLabel} (opens in a new tab)`
    )
    cardBody.appendChild(documentation)
    card.append(cardSummary, cardBody)
    return card
  }

  let manualDialect = false
  const render = () => {
    if (!element.open) return
    const visible = filterQueryLanguageGuides(
      orderedGuides,
      dialectSelect.value,
      search.value,
      productLabel
    )
    resultCount.textContent = `${visible.length} of ${orderedGuides.length} guides`
    cards.textContent = ""
    if (visible.length === 0) {
      cards.appendChild(
        text(
          "p",
          "No guide contains every term. Try a command, field, option or product.",
          {
            padding: "12px",
            "border-radius": "9px",
            "font-size": "11px",
            color: muted,
            border: `1px dashed ${strongLine}`
          }
        )
      )
      return
    }
    for (const guide of visible) {
      cards.appendChild(makeGuideCard(guide, visible.length === 1))
    }
  }

  dialectSelect.addEventListener("change", () => {
    manualDialect = true
    render()
  })
  search.addEventListener("input", render)
  element.addEventListener("toggle", () => {
    guideState.textContent = element.open ? "Close" : "Open"
    element.style.setProperty(
      "flex",
      constrained && element.open ? "1 1 0%" : "0 0 auto",
      "important"
    )
    element.style.setProperty("min-height", "0", "important")
    element.style.setProperty(
      "max-height",
      constrained && element.open ? "100%" : "none",
      "important"
    )
    content.style.setProperty(
      "max-height",
      !constrained
        ? "none"
        : element.open
          ? "none"
          : "min(52vh, 560px)",
      "important"
    )
    content.style.setProperty(
      "position",
      constrained && element.open ? "absolute" : "static",
      "important"
    )
    content.style.setProperty(
      "top",
      constrained && element.open
        ? `${summary.getBoundingClientRect().height}px`
        : "auto",
      "important"
    )
    content.style.setProperty(
      "right",
      constrained && element.open ? "0" : "auto",
      "important"
    )
    content.style.setProperty(
      "bottom",
      constrained && element.open ? "0" : "auto",
      "important"
    )
    content.style.setProperty(
      "left",
      constrained && element.open ? "0" : "auto",
      "important"
    )
    content.style.setProperty("height", "auto", "important")
    content.style.setProperty("flex", "initial", "important")
    content.style.setProperty("min-height", "0", "important")
    content.style.setProperty(
      "overflow-y",
      constrained ? "auto" : "visible",
      "important"
    )
    if (element.open) render()
  })

  content.append(controls, resultCount, cards)
  element.append(summary, content)

  return {
    element,
    syncDialect: (dialectId) => {
      if (
        manualDialect ||
        !QUERY_LANGUAGE_GUIDES.some((guide) => guide.dialectId === dialectId)
      ) {
        return
      }
      dialectSelect.value = dialectId
      if (element.open) render()
    }
  }
}
