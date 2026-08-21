import {
  buildVisualCandidate,
  captureVisualSelection,
  readRenderedElementText,
  visualSelectionText,
  type VisualSelectionSnapshot
} from "./visualFormatting"

export type SmartFormatKind =
  | "json"
  | "partial-json"
  | "semantic-table"
  | "semantic-key-value"
  | "visual-key-value"
  | "delimited-table"
  | "cef"
  | "logfmt"
  | "text-key-value"

export type SmartFormatResult = {
  kind: SmartFormatKind
  score: number
  text: string
}

type Matrix = {
  rows: string[][]
  headers?: string[]
  semanticHeaders: boolean
  explicitHeaders: boolean
  source: "table" | "grid"
}

const cleanText = (value: string | null | undefined): string =>
  (value ?? "")
    .replace(/\u00a0/g, " ")
    .replace(/[\u200b-\u200d\ufeff]/g, "")
    .replace(/[\t ]+/g, " ")
    .replace(/\s*\n\s*/g, " ")
    .trim()

const unique = <T>(values: T[]): T[] => Array.from(new Set(values))

const normalizeLabel = (value: string): string =>
  cleanText(value)
    .replace(/^[-•]\s*/, "")
    .replace(/[\s:：=.-]+$/, "")
    .trim()

const looksLikeStandaloneValue = (value: string): boolean => {
  const text = cleanText(value)
  return (
    /^https?:\/\//i.test(text) ||
    /^\w+:\/\//i.test(text) ||
    /^\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$/.test(text) ||
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(text) ||
    /^\/?(?:[A-Za-z]:\\|[\w.-]+\/)[^\s]*$/.test(text) ||
    /^(?:[A-Fa-f0-9]{0,4}:){2,}[A-Fa-f0-9]{0,4}$/.test(text) ||
    /^[A-Fa-f0-9]{32,128}$/.test(text) ||
    /^\S+@\S+\.\S+$/.test(text)
  )
}

const isLikelyLabel = (value: string): boolean => {
  const label = normalizeLabel(value)
  if (!label || label.length > 96 || looksLikeStandaloneValue(label))
    return false
  if (!/[\p{L}\p{N}]/u.test(label)) return false
  if (/^[\d\W_]+$/u.test(label)) return false
  return label.split(/\s+/).length <= 12
}

const escapeMarkdownCell = (value: string): string =>
  cleanText(value).replace(/\\/g, "\\\\").replace(/\|/g, "\\|")

const formatKeyValues = (pairs: Array<[string, string]>): string => {
  const cleaned = pairs
    .map(([key, value]) => [normalizeLabel(key), cleanText(value)] as const)
    .filter(([key, value]) => key && value)
  if (cleaned.length === 0) return ""
  const labels = cleaned.map(([key]) => `${key}:`)
  const width = Math.min(96, Math.max(...labels.map((label) => label.length)))
  return cleaned
    .map(([_, value], index) => `${labels[index].padEnd(width, " ")} ${value}`)
    .join("\n")
}

const normalizeMatrix = (rows: string[][], columnCount: number): string[][] =>
  rows.map((row) => {
    const normalized = row.slice(0, columnCount).map(cleanText)
    while (normalized.length < columnCount) normalized.push("")
    return normalized
  })

const formatMarkdownTable = (rows: string[][], headers?: string[]): string => {
  const columnCount = Math.max(
    headers?.length ?? 0,
    ...rows.map((row) => row.length)
  )
  if (!Number.isFinite(columnCount) || columnCount <= 0) return ""

  const normalizedRows = normalizeMatrix(rows, columnCount)
  const normalizedHeaders = normalizeMatrix(
    [
      headers?.length
        ? headers
        : Array.from(
            { length: columnCount },
            (_, index) => `Column ${index + 1}`
          )
    ],
    columnCount
  )[0]

  const render = (row: string[]) =>
    `| ${row.map(escapeMarkdownCell).join(" | ")} |`
  return [
    render(normalizedHeaders),
    `| ${Array.from({ length: columnCount }, () => "---").join(" | ")} |`,
    ...normalizedRows.map(render)
  ].join("\n")
}

const removeNoise = (container: HTMLElement): void => {
  container
    .querySelectorAll(
      "script, style, noscript, template, iframe, object, embed, svg, img, [hidden], [aria-hidden='true']"
    )
    .forEach((element) => element.remove())

  container.querySelectorAll<HTMLElement>("*").forEach((element) => {
    const inlineStyle = element.getAttribute("style") ?? ""
    if (/display\s*:\s*none|visibility\s*:\s*hidden/i.test(inlineStyle)) {
      element.remove()
      return
    }

    const marker = `${element.id} ${element.className} ${element.getAttribute("data-testid") ?? ""}`
    const isControl = element.matches("button, [role='button']")
    if (isControl && /\b(copy|clipboard|expand|collapse)\b/i.test(marker)) {
      element.remove()
    }
  })

  container.querySelectorAll("br").forEach((element) => {
    element.replaceWith(container.ownerDocument.createTextNode("\n"))
  })
}

const readElementText = (element: HTMLElement): string => {
  if (element.isConnected) {
    return cleanText(readRenderedElementText(element))
  }
  const clone = element.cloneNode(true) as HTMLElement
  removeNoise(clone)
  return cleanText(clone.textContent)
}

const TABLE_ROOT_SELECTOR = "table, [role='grid'], [role='table']"
const TABLE_ROW_SELECTOR = "tr, [role='row']"
const TABLE_CELL_SELECTOR =
  "td, th, [role='columnheader'], [role='rowheader'], [role='gridcell'], [role='cell']"

const directCells = (row: Element): HTMLElement[] =>
  Array.from(row.querySelectorAll<HTMLElement>(TABLE_CELL_SELECTOR)).filter(
    (cell) => {
      if (cell.closest(TABLE_ROW_SELECTOR) !== row) return false
      const parentCell = cell.parentElement?.closest(TABLE_CELL_SELECTOR)
      return !parentCell || parentCell.closest(TABLE_ROW_SELECTOR) !== row
    }
  )

const rowsForRoot = (root: Element, selector: string): Element[] =>
  Array.from(root.querySelectorAll(selector)).filter((row) => {
    if (row.closest(TABLE_ROOT_SELECTOR) !== root) return false
    const parentRow = row.parentElement?.closest(TABLE_ROW_SELECTOR)
    return !parentRow || parentRow.closest(TABLE_ROOT_SELECTOR) !== root
  })

const getCellIndex = (cell: HTMLElement, fallback: number): number => {
  const raw = Number(cell.getAttribute("aria-colindex"))
  return Number.isInteger(raw) && raw > 0 ? raw - 1 : fallback
}

type CellPlacement = {
  cell: HTMLElement
  index: number
  span: number
}

const placeRowCells = (row: Element): CellPlacement[] => {
  let nextIndex = 0
  return directCells(row).map((cell) => {
    const index = getCellIndex(cell, nextIndex)
    const span = Math.max(1, Number(cell.getAttribute("colspan")) || 1)
    nextIndex = Math.max(nextIndex, index + span)
    return { cell, index, span }
  })
}

const placeRows = (rows: Element[]): CellPlacement[][] => {
  const rowSpans = new Map<number, number>()

  return rows.map((row) => {
    const blocked = new Set(rowSpans.keys())
    const used = new Set<number>()
    const pendingRowSpans: Array<{
      index: number
      span: number
      rows: number
    }> = []
    let nextIndex = 0

    const placements = directCells(row).map((cell) => {
      const explicitIndex = Number(cell.getAttribute("aria-colindex"))
      const hasExplicitIndex =
        Number.isInteger(explicitIndex) && explicitIndex > 0
      const span = Math.max(1, Number(cell.getAttribute("colspan")) || 1)
      let index = hasExplicitIndex ? explicitIndex - 1 : nextIndex

      while (
        !hasExplicitIndex &&
        Array.from({ length: span }, (_, offset) => index + offset).some(
          (column) => blocked.has(column) || used.has(column)
        )
      ) {
        index += 1
      }

      for (let offset = 0; offset < span; offset += 1) {
        used.add(index + offset)
      }
      nextIndex = Math.max(nextIndex, index + span)

      const rowsSpanned = Math.max(1, Number(cell.getAttribute("rowspan")) || 1)
      if (rowsSpanned > 1) {
        pendingRowSpans.push({ index, span, rows: rowsSpanned - 1 })
      }
      return { cell, index, span }
    })

    rowSpans.forEach((remaining, column) => {
      if (remaining <= 1) rowSpans.delete(column)
      else rowSpans.set(column, remaining - 1)
    })
    pendingRowSpans.forEach(({ index, span, rows: remaining }) => {
      for (let offset = 0; offset < span; offset += 1) {
        rowSpans.set(index + offset, remaining)
      }
    })

    return placements
  })
}

const readRow = (
  row: Element
): { cells: string[]; headerCells: boolean } | null => {
  const cells = directCells(row)
  if (cells.length === 0) return null

  const indexed = placeRowCells(row).map(({ cell, index, span }) => ({
    index,
    span,
    text: readElementText(cell)
  }))
  const width = Math.max(...indexed.map((cell) => cell.index + cell.span))
  const values = Array.from({ length: width }, () => "")
  indexed.forEach((cell) => {
    values[cell.index] = cell.text
  })

  const headerCells = cells.every((cell) =>
    cell.matches("th, [role='columnheader']")
  )
  return values.some(Boolean) ? { cells: values, headerCells } : null
}

const readRows = (
  rows: Element[]
): Array<{ cells: string[]; headerCells: boolean }> =>
  placeRows(rows)
    .map((placements, rowIndex) => {
      if (placements.length === 0) return null
      const width = Math.max(
        ...placements.map(({ index, span }) => index + span)
      )
      const values = Array.from({ length: width }, () => "")
      placements.forEach(({ cell, index }) => {
        values[index] = readElementText(cell)
      })
      const cells = directCells(rows[rowIndex])
      return values.some(Boolean)
        ? {
            cells: values,
            headerCells: cells.every((cell) =>
              cell.matches("th, [role='columnheader']")
            )
          }
        : null
    })
    .filter((row): row is NonNullable<typeof row> => !!row)

const splitMatrixRows = (
  parsed: Array<{ cells: string[]; headerCells: boolean }>
): { rows: string[][]; headers?: string[]; explicitHeaders: boolean } => {
  const headerRows = parsed.filter(({ headerCells }) => headerCells)
  const rows = parsed
    .filter(({ headerCells }) => !headerCells)
    .map(({ cells }) => cells)
  if (headerRows.length === 0) {
    return { rows, explicitHeaders: false }
  }

  const columnCount = Math.max(
    ...headerRows.map(({ cells }) => cells.length),
    ...rows.map((row) => row.length),
    0
  )
  const headers = Array.from({ length: columnCount }, () => "")
  headerRows.forEach(({ cells }) => {
    cells.forEach((cell, index) => {
      if (cell) headers[index] = cell
    })
  })
  return { rows, headers, explicitHeaders: true }
}

const inferHeadersFromCells = (
  rows: Element[],
  columnCount: number
): string[] | undefined => {
  const headers = Array.from({ length: columnCount }, () => "")
  const layouts = placeRows(rows)
  rows.forEach((row, rowIndex) => {
    layouts[rowIndex].forEach(({ cell, index }) => {
      if (headers[index]) return
      const label =
        cell.getAttribute("data-column-name") ??
        cell.getAttribute("data-field-name") ??
        cell.getAttribute("aria-label")
      if (label && isLikelyLabel(label)) headers[index] = normalizeLabel(label)
    })
  })
  return headers.every(Boolean) ? headers : undefined
}

const extractSemanticMatrices = (
  container: HTMLElement,
  contextualHeaders: string[] = []
): Matrix[] => {
  const matrices: Matrix[] = []
  const orphanCells = directCells(container)
  if (orphanCells.length >= 2) {
    const width = Math.max(
      ...orphanCells.map((cell, index) => getCellIndex(cell, index) + 1)
    )
    const values = Array.from({ length: width }, () => "")
    orphanCells.forEach((cell, index) => {
      values[getCellIndex(cell, index)] = readElementText(cell)
    })
    matrices.push({
      rows: [values],
      headers:
        contextualHeaders.length === width ? contextualHeaders : undefined,
      semanticHeaders: contextualHeaders.length === width,
      explicitHeaders: false,
      source: orphanCells.some((cell) => cell.matches("td, th"))
        ? "table"
        : "grid"
    })
  }

  const orphanRows = Array.from(
    container.querySelectorAll("tr, [role='row']")
  ).filter(
    (row) =>
      !row.closest("table, [role='grid'], [role='table']") &&
      directCells(row).length > 0
  )
  if (orphanRows.length > 0) {
    const parsed = orphanRows
      .map(readRow)
      .filter((row): row is NonNullable<typeof row> => !!row)
    const split = splitMatrixRows(parsed)
    const { rows } = split
    if (rows.length > 0) {
      const count = Math.max(...rows.map((row) => row.length))
      matrices.push({
        rows,
        headers: split.headers
          ? split.headers
          : contextualHeaders.length === count
            ? contextualHeaders
            : undefined,
        semanticHeaders:
          split.explicitHeaders || contextualHeaders.length === count,
        explicitHeaders: split.explicitHeaders,
        source: orphanRows.some((row) => row.matches("tr")) ? "table" : "grid"
      })
    }
  }

  const tableRoots: Element[] = Array.from(container.querySelectorAll("table"))
  if (container.matches("table")) tableRoots.unshift(container)

  tableRoots.forEach((table) => {
    const rowElements = rowsForRoot(table, "tr")
    const parsed = readRows(rowElements)
    if (parsed.length === 0) return
    const split = splitMatrixRows(parsed)
    const { headers, rows } = split
    if (rows.length === 0) return
    const count = Math.max(
      ...rows.map((row) => row.length),
      headers?.length ?? 0
    )
    matrices.push({
      rows,
      headers:
        headers ??
        (contextualHeaders.length === count ? contextualHeaders : undefined) ??
        inferHeadersFromCells(rowElements, count),
      semanticHeaders:
        split.explicitHeaders || contextualHeaders.length === count,
      explicitHeaders: split.explicitHeaders,
      source: "table"
    })
  })

  const gridRoots = Array.from(
    container.querySelectorAll<HTMLElement>("[role='grid'], [role='table']")
  )
  if (container.matches("[role='grid'], [role='table']"))
    gridRoots.unshift(container)

  gridRoots.forEach((grid) => {
    const rowElements = rowsForRoot(grid, "[role='row']")
    const parsed = readRows(rowElements)
    if (parsed.length === 0) return
    const split = splitMatrixRows(parsed)
    const { headers, rows } = split
    if (rows.length === 0) return
    const count = Math.max(
      ...rows.map((row) => row.length),
      headers?.length ?? 0
    )
    matrices.push({
      rows,
      headers:
        headers ??
        (contextualHeaders.length === count ? contextualHeaders : undefined) ??
        inferHeadersFromCells(rowElements, count),
      semanticHeaders:
        split.explicitHeaders || contextualHeaders.length === count,
      explicitHeaders: split.explicitHeaders,
      source: "grid"
    })
  })

  return matrices
}

const matrixCandidate = (matrix: Matrix): SmartFormatResult | null => {
  const columnCount = Math.max(
    ...matrix.rows.map((row) => row.length),
    matrix.headers?.length ?? 0
  )
  if (columnCount < 2) return null

  const normalizedRows = normalizeMatrix(matrix.rows, columnCount)
  const firstColumnIsLabels = normalizedRows.every(
    (row) => row[0] && row[1] && isLikelyLabel(row[0])
  )
  const firstColumnUnique =
    new Set(normalizedRows.map((row) => normalizeLabel(row[0]).toLowerCase()))
      .size === normalizedRows.length
  const rowHeaderSignal =
    matrix.headers?.[0]?.toLowerCase().includes("field") === true
  const isKeyValue =
    columnCount === 2 &&
    firstColumnIsLabels &&
    firstColumnUnique &&
    (!matrix.semanticHeaders || rowHeaderSignal)

  if (isKeyValue) {
    return {
      kind: "semantic-key-value",
      score: matrix.source === "table" ? 91 : 89,
      text: formatKeyValues(normalizedRows.map((row) => [row[0], row[1]]))
    }
  }

  return {
    kind: "semantic-table",
    score: matrix.explicitHeaders
      ? 99
      : matrix.semanticHeaders
        ? 96
        : matrix.source === "table"
          ? 91
          : 89,
    text: formatMarkdownTable(normalizedRows, matrix.headers)
  }
}

const extractSemanticPairs = (
  container: HTMLElement
): Array<[string, string]> => {
  const pairs: Array<[string, string]> = []
  const containerLabelCount = container.querySelectorAll("label").length

  const addPair = (
    key: string | null | undefined,
    value: string | null | undefined
  ) => {
    const normalizedKey = normalizeLabel(key ?? "")
    const normalizedValue = cleanText(value)
    if (
      isLikelyLabel(normalizedKey) &&
      normalizedValue &&
      normalizedKey.toLowerCase() !== normalizedValue.toLowerCase()
    ) {
      pairs.push([normalizedKey, normalizedValue])
    }
  }

  const readValueWithoutControls = (
    root: Element,
    excluded?: Element
  ): string => {
    const clone = root.cloneNode(true) as HTMLElement
    if (excluded) {
      const path: number[] = []
      let current: Element | null = excluded
      while (current && current !== root) {
        const parent: Element | null = current.parentElement
        if (!parent) break
        path.unshift(Array.from(parent.children).indexOf(current))
        current = parent
      }
      let clonedExcluded: Element | null = clone
      path.forEach((index) => {
        clonedExcluded = clonedExcluded?.children[index] ?? null
      })
      clonedExcluded?.remove()
    }
    removeNoise(clone)
    clone
      .querySelectorAll(
        "label, button, input, select, textarea, [role='button'], [role='checkbox'], [role='tab'], [role='switch']"
      )
      .forEach((element) => element.remove())
    return cleanText(clone.textContent)
  }

  const readVisibleText = (root: Element): string => {
    const clone = root.cloneNode(true) as HTMLElement
    removeNoise(clone)
    return cleanText(clone.textContent)
  }

  const closestLabelValueContainer = (
    label: HTMLElement
  ): HTMLElement | null => {
    let candidate = label.parentElement
    for (let depth = 0; candidate && depth < 6; depth += 1) {
      if (candidate === container && containerLabelCount > 2) break
      const visibleLabels = Array.from(
        candidate.querySelectorAll("label")
      ).filter(
        (item) =>
          !item.hidden &&
          item.getAttribute("aria-hidden") !== "true" &&
          cleanText(item.textContent)
      )
      if (visibleLabels.length === 1) {
        const value = readValueWithoutControls(candidate, label)
        if (value && value.length <= 2_000) return candidate
      }
      if (candidate === container) break
      candidate = candidate.parentElement
    }
    return null
  }

  container.querySelectorAll("dt").forEach((term) => {
    const value = term.nextElementSibling
    if (!value?.matches("dd")) return
    addPair(
      readElementText(term as HTMLElement),
      readElementText(value as HTMLElement)
    )
  })

  container.querySelectorAll<HTMLElement>("label").forEach((label) => {
    if (
      label.hidden ||
      label.getAttribute("aria-hidden") === "true" ||
      label.matches(".checkbox, [class*='checkbox']")
    ) {
      return
    }
    const targetId = label.getAttribute("for")
    const target = targetId
      ? container.querySelector<HTMLElement>(`#${CSS.escape(targetId)}`)
      : null
    const keyText = cleanText(label.textContent)
    if (!isLikelyLabel(keyText)) return

    if (
      target instanceof HTMLInputElement ||
      target instanceof HTMLTextAreaElement ||
      target instanceof HTMLSelectElement
    ) {
      addPair(keyText, target.value)
      return
    }

    if (target) {
      const targetValue = readValueWithoutControls(target)
      if (targetValue && targetValue.toLowerCase() !== keyText.toLowerCase()) {
        addPair(keyText, targetValue)
        return
      }
    }

    const pairContainer = closestLabelValueContainer(label)
    if (pairContainer) {
      addPair(keyText, readValueWithoutControls(pairContainer, label))
      return
    }

    const sibling = label.nextElementSibling
    if (sibling) addPair(keyText, readValueWithoutControls(sibling))
  })

  const attributeSelectors = [
    "data-field-name",
    "data-field",
    "context-data-property",
    "data-column-name"
  ]
  const attributeCandidates = new Map<
    string,
    Array<{ value: string; score: number }>
  >()
  const attributeSelector = attributeSelectors
    .map((attribute) => `[${attribute}]`)
    .join(", ")
  const attributedElements = [
    ...(container.matches(attributeSelector) ? [container] : []),
    ...Array.from(container.querySelectorAll<HTMLElement>(attributeSelector))
  ]
  attributedElements.forEach((element) => {
    const attribute = attributeSelectors.find((name) =>
      element.hasAttribute(name)
    )
    const keyText = attribute ? element.getAttribute(attribute) : ""
    if (!keyText || !isLikelyLabel(keyText)) return

    const nestedWithSameKey = attribute
      ? Array.from(
          element.querySelectorAll<HTMLElement>(`[${attribute}]`)
        ).some((child) => child.getAttribute(attribute) === keyText)
      : false
    if (nestedWithSameKey) return

    const marker = `${element.className} ${element.getAttribute("data-test") ?? ""}`
    if (
      element.matches(
        "label, button, [role='button'], [role='checkbox'], [role='tab'], [role='switch']"
      ) ||
      /\b(action|field-info|toggle|checkbox)\b/i.test(marker)
    ) {
      return
    }

    const valueText =
      attribute === "context-data-property"
        ? readVisibleText(element)
        : readValueWithoutControls(element)
    if (
      !valueText ||
      normalizeLabel(keyText).toLowerCase() === valueText.toLowerCase()
    ) {
      return
    }

    let score = 0
    if (/\bf-v\b|\bvalue\b/i.test(marker)) score += 4
    if (element.hasAttribute("context-data-value")) score += 4
    if (element.children.length === 0) score += 2
    if (valueText.length <= 512) score += 1
    const candidates = attributeCandidates.get(keyText) ?? []
    candidates.push({ value: valueText, score })
    attributeCandidates.set(keyText, candidates)
  })

  attributeCandidates.forEach((candidates, key) => {
    const best = candidates.sort(
      (left, right) =>
        right.score - left.score || left.value.length - right.value.length
    )[0]
    if (best) addPair(key, best.value)
  })

  container
    .querySelectorAll<HTMLElement>("[role='gridcell'], [role='cell']")
    .forEach((cell) => {
      const segments = Array.from(cell.children)
        .map((child) => readElementText(child as HTMLElement))
        .filter(Boolean)
      if (segments.length < 2 || !isLikelyLabel(segments[0])) return
      const value = segments.slice(1).join(" ")
      addPair(segments[0], value)
    })

  container.querySelectorAll<HTMLElement>("strong").forEach((label) => {
    const keyText = readElementText(label)
    if (!/[:：]\s*$/.test(keyText) || !isLikelyLabel(keyText)) return
    const value = label.nextElementSibling
    if (value) addPair(keyText, readElementText(value as HTMLElement))
  })

  return unique(
    pairs.map(
      ([key, value]) => `${normalizeLabel(key)}\u0000${cleanText(value)}`
    )
  ).map((pair) => pair.split("\u0000") as [string, string])
}

const tryJson = (value: string): string | null => {
  const text = value.trim()
  if (!(
    (text.startsWith("{") && text.endsWith("}")) ||
    (text.startsWith("[") && text.endsWith("]"))
  )) {
    return null
  }
  const attempts = [text, text.replace(/,\s*([}\]])/g, "$1")]
  for (const attempt of attempts) {
    try {
      return `\`\`\`json\n${JSON.stringify(JSON.parse(attempt), null, 2)}\n\`\`\``
    } catch {
      // Try the next conservative normalization.
    }
  }
  return null
}

const decodePartialJsonWhitespace = (value: string): string =>
  value
    .replace(
      /&(?:nbsp|ensp|emsp|thinsp);|&#(?:0*32|0*160);|&#x(?:0*20|0*a0);/gi,
      " "
    )
    .replace(/\u00a0/g, " ")
    .replace(/[\u200b-\u200d\ufeff]/g, "")

const normalizePartialJsonCommaMarkers = (value: string): string => {
  let result = ""
  let quoted = false
  let escaped = false

  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]
    if (quoted) {
      result += character
      if (escaped) escaped = false
      else if (character === "\\") escaped = true
      else if (character === '"') quoted = false
      continue
    }

    if (character === '"') {
      quoted = true
      result += character
      continue
    }

    if (character === "*") {
      const marker = value.slice(index).match(/^\*\s*,\s*\*/)
      if (marker) {
        result += ","
        index += marker[0].length - 1
        continue
      }
    }
    result += character
  }
  return result
}

const normalizePartialJsonStrings = (
  value: string
): { text: string; propertyCount: number } | null => {
  let result = ""
  let propertyCount = 0
  let previousSignificant = ""

  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]
    if (character !== '"') {
      result += character
      if (!/\s/.test(character)) previousSignificant = character
      continue
    }

    let content = ""
    let closed = false
    index += 1
    for (; index < value.length; index += 1) {
      const stringCharacter = value[index]
      if (stringCharacter === "\\" && index + 1 < value.length) {
        content += stringCharacter + value[index + 1]
        index += 1
      } else if (stringCharacter === '"') {
        closed = true
        break
      } else {
        content += stringCharacter
      }
    }
    if (!closed) return null

    let lookahead = index + 1
    while (lookahead < value.length && /\s/.test(value[lookahead])) {
      lookahead += 1
    }
    const isProperty = value[lookahead] === ":"
    if (isProperty) {
      propertyCount += 1
      // A backslash before an underscore is a common Markdown-copy artifact,
      // but is not a legal JSON escape sequence.
      content = content.trim().replace(/\\_/g, "_")
    } else if (previousSignificant === ":") {
      content = content.trim()
    }

    result += `"${content}"`
    previousSignificant = '"'
  }

  return { text: result, propertyCount }
}

const closePartialJsonStructure = (value: string): string | null => {
  const stack: Array<"{" | "["> = []
  let quoted = false
  let escaped = false

  for (const character of value) {
    if (quoted) {
      if (escaped) escaped = false
      else if (character === "\\") escaped = true
      else if (character === '"') quoted = false
      continue
    }

    if (character === '"') quoted = true
    else if (character === "{" || character === "[") stack.push(character)
    else if (character === "}" || character === "]") {
      const expected = character === "}" ? "{" : "["
      if (stack.pop() !== expected) return null
    }
  }

  if (quoted || escaped) return null
  const withoutTrailingComma = value.replace(/,\s*$/, "")
  const suffix = stack
    .reverse()
    .map((opening) => (opening === "{" ? "}" : "]"))
    .join("")
  return `${withoutTrailingComma}${suffix}`.replace(/,\s*([}\]])/g, "$1")
}

const tryPartialJson = (value: string): string | null => {
  let text = decodePartialJsonWhitespace(value).trim()
  if (!text) return null

  // Ignore emphasis markers sometimes introduced around commas by copied
  // Markdown, while leaving ordinary asterisks inside strings untouched.
  text = normalizePartialJsonCommaMarkers(text)
  const normalized = normalizePartialJsonStrings(text)
  if (!normalized || normalized.propertyCount === 0) return null

  text = normalized.text
  if (!text.startsWith("{") && !text.startsWith("[")) text = `{${text}`
  const completed = closePartialJsonStructure(text)
  if (!completed) return null

  try {
    const parsed = JSON.parse(completed)
    if (!parsed || typeof parsed !== "object") return null
    return `\`\`\`json\n${JSON.stringify(parsed, null, 2)}\n\`\`\``
  } catch {
    return null
  }
}

const extractJsonCandidate = (
  container: HTMLElement
): SmartFormatResult | null => {
  const sources = unique([
    container.textContent ?? "",
    ...Array.from(
      container.querySelectorAll("pre, code, textarea, [data-json], [data-raw]")
    ).map(
      (element) =>
        element.getAttribute("data-json") ??
        element.getAttribute("data-raw") ??
        element.textContent ??
        ""
    ),
    cleanTextPreservingLines(container.textContent)
  ])

  for (const source of sources) {
    const formatted = tryJson(source)
    if (formatted) return { kind: "json", score: 100, text: formatted }
  }

  for (const source of sources) {
    const formatted = tryPartialJson(source)
    if (formatted) {
      return { kind: "partial-json", score: 96, text: formatted }
    }
  }

  const jsonLines = sources
    .flatMap((source) => source.split(/\r?\n/))
    .map(tryJson)
    .filter((value): value is string => !!value)
  if (jsonLines.length > 1) {
    return { kind: "json", score: 97, text: jsonLines.join("\n\n") }
  }
  return null
}

const cleanTextPreservingLines = (value: string | null | undefined): string =>
  (value ?? "")
    .replace(/\u00a0/g, " ")
    .replace(/[\u200b-\u200d\ufeff]/g, "")
    .replace(/\r/g, "")
    .split("\n")
    .map((line) => line.replace(/ +/g, " ").trim())
    .filter(Boolean)
    .join("\n")

const parseDelimitedLine = (line: string, delimiter: string): string[] => {
  const cells: string[] = []
  let current = ""
  let quoted = false
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index]
    if (character === '"') {
      if (quoted && line[index + 1] === '"') {
        current += '"'
        index += 1
      } else {
        quoted = !quoted
      }
    } else if (character === delimiter && !quoted) {
      cells.push(cleanText(current))
      current = ""
    } else {
      current += character
    }
  }
  cells.push(cleanText(current))
  return cells
}

const extractDelimitedCandidate = (text: string): SmartFormatResult | null => {
  const lines = text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
  if (lines.length < 2) return null

  for (const delimiter of ["\t", ",", ";", "|"]) {
    const rows = lines.map((line) => parseDelimitedLine(line, delimiter))
    const counts = rows.map((row) => row.length)
    const columnCount = counts[0]
    if (columnCount < 2 || !counts.every((count) => count === columnCount))
      continue
    const firstRowLooksLikeHeader = rows[0].every(isLikelyLabel)
    const headers = firstRowLooksLikeHeader ? rows[0] : undefined
    const dataRows = firstRowLooksLikeHeader ? rows.slice(1) : rows
    if (dataRows.length === 0) continue
    return {
      kind: "delimited-table",
      score: firstRowLooksLikeHeader ? 88 : 82,
      text: formatMarkdownTable(dataRows, headers)
    }
  }
  return null
}

const LOGFMT_KEY_PATTERN = /(?:^|\s)([A-Za-z_][\w.-]{0,95})=/g

const parseLogfmt = (line: string): Array<[string, string]> => {
  const matches = Array.from(line.matchAll(LOGFMT_KEY_PATTERN))
  return matches.map((match, index) => {
    const matchStart = match.index ?? 0
    const valueStart = matchStart + match[0].length
    const valueEnd = matches[index + 1]?.index ?? line.length
    let value = line.slice(valueStart, valueEnd).trim()
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1)
    }
    return [match[1], value] as [string, string]
  })
}

const splitCef = (text: string): string[] => {
  const parts: string[] = []
  let current = ""
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index]
    const next = text[index + 1]
    if (character === "\\" && (next === "|" || next === "\\")) {
      current += next
      index += 1
    } else if (character === "|" && parts.length < 7) {
      parts.push(current)
      current = ""
    } else {
      current += character
    }
  }
  parts.push(current)
  return parts
}

const parseCef = (text: string): SmartFormatResult | null => {
  if (!/^CEF:\d+\|/i.test(text)) return null
  const parts = splitCef(text)
  if (parts.length < 8) return null
  const header: Array<[string, string]> = [
    ["Format", parts[0]],
    ["Vendor", parts[1]],
    ["Product", parts[2]],
    ["Version", parts[3]],
    ["Signature ID", parts[4]],
    ["Event", parts[5]],
    ["Severity", parts[6]]
  ]
  const extension = parseLogfmt(parts.slice(7).join("|"))
  return {
    kind: "cef",
    score: 95,
    text: formatKeyValues([...header, ...extension])
  }
}

const parseKeyValueLine = (line: string): [string, string] | null => {
  const candidates = [
    /^\s*[-•]?\s*(.{1,96}?)\s*[:：]\s*(.+)$/,
    /^\s*[-•]?\s*(.{1,96}?)\s*=\s*(.+)$/,
    /^\s*[-•]?\s*(.{1,96}?)\t+(.+)$/,
    /^\s*[-•]?\s*(.{1,96}?)\s+\.{2,}\s+(.+)$/
  ]
  for (const pattern of candidates) {
    const match = line.match(pattern)
    if (!match) continue
    const key = normalizeLabel(match[1])
    const value = cleanText(match[2])
    if (isLikelyLabel(key) && value && !looksLikeStandaloneValue(line))
      return [key, value]
  }
  return null
}

const parseAlternatingKeyValueLines = (
  lines: string[]
): Array<[string, string]> => {
  if (lines.length < 6 || lines.length % 2 !== 0) return []
  const pairs: Array<[string, string]> = []
  for (let index = 0; index < lines.length; index += 2) {
    const key = lines[index]
    const value = lines[index + 1]
    if (
      !isLikelyLabel(key) ||
      !value ||
      value.length > 512 ||
      normalizeLabel(key).toLowerCase() === cleanText(value).toLowerCase()
    ) {
      return []
    }
    pairs.push([key, value])
  }

  const uniqueKeys = new Set(
    pairs.map(([key]) => normalizeLabel(key).toLowerCase())
  )
  const sentenceValues = pairs.filter(([, value]) =>
    /[.!?]\s*$/.test(value)
  ).length
  if (uniqueKeys.size !== pairs.length || sentenceValues > pairs.length / 2) {
    return []
  }
  return pairs
}

const extractTextCandidate = (text: string): SmartFormatResult | null => {
  const cef = parseCef(text)
  if (cef) return cef

  const lines = text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
  const allLogfmt = lines.flatMap(parseLogfmt)
  if (allLogfmt.length >= 2) {
    return { kind: "logfmt", score: 90, text: formatKeyValues(allLogfmt) }
  }

  const alternatingPairs = parseAlternatingKeyValueLines(lines)
  if (alternatingPairs.length >= 3) {
    return {
      kind: "text-key-value",
      score: Math.min(88, 80 + alternatingPairs.length),
      text: formatKeyValues(alternatingPairs)
    }
  }

  const pairs = lines
    .map(parseKeyValueLine)
    .filter((pair): pair is [string, string] => !!pair)
  if (pairs.length === 0) return null
  const coverage = pairs.length / Math.max(lines.length, 1)
  if (coverage < 0.5 && pairs.length < 3) return null
  return {
    kind: "text-key-value",
    score: Math.min(
      89,
      72 + Math.round(coverage * 12) + Math.min(pairs.length, 5)
    ),
    text: formatKeyValues(pairs)
  }
}

export const formatSmartContainer = (
  source: HTMLElement,
  contextualHeaders: string[] = []
): SmartFormatResult | null => {
  const container = source.cloneNode(true) as HTMLElement
  removeNoise(container)
  const text = cleanTextPreservingLines(container.textContent)
  const candidates: SmartFormatResult[] = []
  const matrixPairs: Array<[string, string]> = []

  const json = extractJsonCandidate(container)
  if (json) candidates.push(json)

  extractSemanticMatrices(container, contextualHeaders).forEach((matrix) => {
    const candidate = matrixCandidate(matrix)
    if (candidate?.text) candidates.push(candidate)
    if (candidate?.kind === "semantic-key-value") {
      matrix.rows.forEach((row) => {
        if (row.length === 2) matrixPairs.push([row[0], row[1]])
      })
    }
  })

  const semanticPairs = unique(
    [...extractSemanticPairs(container), ...matrixPairs].map(
      ([key, value]) => `${normalizeLabel(key)}\u0000${cleanText(value)}`
    )
  ).map((pair) => pair.split("\u0000") as [string, string])
  if (semanticPairs.length > 0) {
    candidates.push({
      kind: "semantic-key-value",
      score: Math.min(98, 86 + semanticPairs.length * 2),
      text: formatKeyValues(semanticPairs)
    })
  }

  const delimited = extractDelimitedCandidate(text)
  if (delimited) candidates.push(delimited)
  const textCandidate = extractTextCandidate(text)
  if (textCandidate) candidates.push(textCandidate)

  return (
    candidates
      .filter((candidate) => candidate.text.trim())
      .sort(
        (left, right) =>
          right.score - left.score || right.text.length - left.text.length
      )[0] ?? null
  )
}

const elementFromNode = (node: Node | null): Element | null => {
  if (!node) return null
  return node.nodeType === Node.ELEMENT_NODE
    ? (node as Element)
    : node.parentElement
}

const readContextualHeaders = (selection: Selection): string[] => {
  if (selection.rangeCount === 0) return []
  const range = selection.getRangeAt(0)
  const start = elementFromNode(range.startContainer)
  const end = elementFromNode(range.endContainer)
  const startRoot = start?.closest("table, [role='grid'], [role='table']")
  const endRoot = end?.closest("table, [role='grid'], [role='table']")
  if (!startRoot || startRoot !== endRoot) return []

  const rows = rowsForRoot(startRoot, TABLE_ROW_SELECTOR)
  return splitMatrixRows(readRows(rows)).headers ?? []
}

const DATA_FIELD_ATTRIBUTES = [
  "data-field-name",
  "data-field",
  "context-data-property",
  "data-column-name"
] as const
const DATA_FIELD_SELECTOR = DATA_FIELD_ATTRIBUTES.map(
  (attribute) => `[${attribute}]`
).join(", ")

const formatMarkedSelection = (
  selection: Selection
): SmartFormatResult | null => {
  if (selection.rangeCount === 0) return null
  const range = selection.getRangeAt(0)
  const start = elementFromNode(range.startContainer)
  const end = elementFromNode(range.endContainer)
  const startData = start?.closest<HTMLElement>(DATA_FIELD_SELECTOR)
  const endData = end?.closest<HTMLElement>(DATA_FIELD_SELECTOR)
  if (!startData || !endData) return null

  const attribute = DATA_FIELD_ATTRIBUTES.find(
    (name) =>
      startData.hasAttribute(name) &&
      endData.hasAttribute(name) &&
      startData.getAttribute(name) === endData.getAttribute(name)
  )
  const key = attribute ? startData.getAttribute(attribute) : null
  if (!attribute || !key) return null

  let candidate: HTMLElement | null = startData
  while (candidate && !candidate.contains(endData)) {
    candidate = candidate.parentElement
  }
  if (!candidate) return null

  if (attribute !== "context-data-property") {
    let groupedCandidate: HTMLElement | null = candidate
    for (let depth = 0; groupedCandidate && depth < 6; depth += 1) {
      const matching = Array.from(
        groupedCandidate.querySelectorAll<HTMLElement>(`[${attribute}]`)
      ).filter((element) => element.getAttribute(attribute) === key)
      if (matching.length >= 2 && matching.length <= 8) {
        candidate = groupedCandidate
        break
      }
      groupedCandidate = groupedCandidate.parentElement
    }
  }

  const normalizedKey = normalizeLabel(key).toLowerCase()
  const matchingElements = [
    ...(candidate.matches(`[${attribute}]`) ? [candidate] : []),
    ...Array.from(candidate.querySelectorAll<HTMLElement>(`[${attribute}]`))
  ].filter((element) => element.getAttribute(attribute) === key)
  const value = matchingElements
    .map((element) => {
      const text = readRenderedElementText(element)
      const marker = `${element.className} ${element.getAttribute("data-test") ?? ""}`
      let score = 0
      if (/\bf-v\b|\bvalue\b/i.test(marker)) score += 5
      if (element.hasAttribute("context-data-value")) score += 5
      if (element.children.length === 0) score += 2
      if (text.length <= 512) score += 1
      return { text, score }
    })
    .filter(
      ({ text }) => text && normalizeLabel(text).toLowerCase() !== normalizedKey
    )
    .sort(
      (left, right) =>
        right.score - left.score || left.text.length - right.text.length
    )[0]?.text
  if (!value) return null
  return {
    kind: "semantic-key-value",
    score: 99,
    text: formatKeyValues([[key, value]])
  }
}

const closestTableCell = (element: Element): HTMLElement | null =>
  element.closest<HTMLElement>(TABLE_CELL_SELECTOR)

const formatSelectedTable = (
  selection: Selection
): SmartFormatResult | null => {
  if (selection.rangeCount === 0) return null
  const range = selection.getRangeAt(0)
  const start = elementFromNode(range.startContainer)
  const end = elementFromNode(range.endContainer)
  if (!start || !end) return null

  // Product-specific field markers carry stronger key/value semantics than
  // their surrounding layout table (for example, a Splunk field row).
  const startData = start.closest(DATA_FIELD_SELECTOR)
  const endData = end.closest(DATA_FIELD_SELECTOR)
  if (startData && endData) {
    const sameField = DATA_FIELD_ATTRIBUTES.some(
      (attribute) =>
        startData.hasAttribute(attribute) &&
        endData.hasAttribute(attribute) &&
        startData.getAttribute(attribute) === endData.getAttribute(attribute)
    )
    if (sameField) return null
  }

  const startCell = closestTableCell(start)
  const endCell = closestTableCell(end)
  const startRoot = startCell?.closest(TABLE_ROOT_SELECTOR)
  const endRoot = endCell?.closest(TABLE_ROOT_SELECTOR)
  if (!startCell || !endCell || !startRoot || startRoot !== endRoot) return null

  const rows = rowsForRoot(startRoot, TABLE_ROW_SELECTOR)
  const rowLayouts = placeRows(rows)
  const layouts = rows.map((row, index) => {
    const cells = directCells(row)
    return {
      row,
      placements: rowLayouts[index],
      header:
        cells.length > 0 &&
        cells.every((cell) => cell.matches("th, [role='columnheader']"))
    }
  })
  const startRowIndex = layouts.findIndex(({ placements }) =>
    placements.some(({ cell }) => cell === startCell)
  )
  const endRowIndex = layouts.findIndex(({ placements }) =>
    placements.some(({ cell }) => cell === endCell)
  )
  if (startRowIndex < 0 || endRowIndex < 0) return null

  const startPlacement = layouts[startRowIndex].placements.find(
    ({ cell }) => cell === startCell
  )
  const endPlacement = layouts[endRowIndex].placements.find(
    ({ cell }) => cell === endCell
  )
  if (!startPlacement || !endPlacement) return null

  const firstColumn = Math.min(startPlacement.index, endPlacement.index)
  const lastColumn = Math.max(
    startPlacement.index + startPlacement.span - 1,
    endPlacement.index + endPlacement.span - 1
  )
  const columnCount = lastColumn - firstColumn + 1
  const firstRow = Math.min(startRowIndex, endRowIndex)
  const lastRow = Math.max(startRowIndex, endRowIndex)

  const sliceLayout = (placements: CellPlacement[]): string[] => {
    const values = Array.from({ length: columnCount }, () => "")
    placements.forEach(({ cell, index, span }) => {
      const overlapStart = Math.max(index, firstColumn)
      const overlapEnd = Math.min(index + span - 1, lastColumn)
      if (overlapStart <= overlapEnd) {
        values[overlapStart - firstColumn] = readElementText(cell)
      }
    })
    return values
  }

  const selectedRows = layouts
    .slice(firstRow, lastRow + 1)
    .filter(({ header }) => !header)
    .map(({ placements }) => sliceLayout(placements))
  if (selectedRows.length === 0) return null

  const headerLayouts = layouts.filter(({ header }) => header)
  const inferredHeaders = inferHeadersFromCells(
    rows,
    Math.max(lastColumn + 1, 1)
  )
  const headers = headerLayouts.length
    ? headerLayouts.reduce<string[]>(
        (combined, { placements }) => {
          sliceLayout(placements).forEach((header, index) => {
            if (header) combined[index] = header
          })
          return combined
        },
        Array.from({ length: columnCount }, () => "")
      )
    : inferredHeaders?.slice(firstColumn, lastColumn + 1)
  const normalizedHeaders = headers?.map(
    (header, index) => header || `Column ${firstColumn + index + 1}`
  )

  return {
    kind: "semantic-table",
    score: normalizedHeaders ? 98 : 93,
    text: formatMarkdownTable(selectedRows, normalizedHeaders)
  }
}

const findAtomicSelectionContainer = (
  selection: Selection
): HTMLElement | null => {
  if (selection.rangeCount === 0) return null
  const range = selection.getRangeAt(0)
  const start = elementFromNode(range.startContainer)
  const end = elementFromNode(range.endContainer)
  if (!start || !end) return null

  const startData = start.closest<HTMLElement>(DATA_FIELD_SELECTOR)
  const endData = end.closest<HTMLElement>(DATA_FIELD_SELECTOR)
  if (startData && startData === endData) {
    const attribute = DATA_FIELD_ATTRIBUTES.find((name) =>
      startData.hasAttribute(name)
    )
    if (attribute === "context-data-property") return startData

    const key = attribute ? startData.getAttribute(attribute) : null
    let candidate = startData.parentElement
    for (
      let depth = 0;
      attribute && key && candidate && depth < 5;
      depth += 1
    ) {
      const matching = Array.from(
        candidate.querySelectorAll<HTMLElement>(`[${attribute}]`)
      ).filter((element) => element.getAttribute(attribute) === key)
      if (matching.length >= 2 && matching.length <= 8) return candidate
      candidate = candidate.parentElement
    }
    return startData
  }

  const startCell = start.closest<HTMLElement>(
    "td, th, [role='gridcell'], [role='cell']"
  )
  const endCell = end.closest<HTMLElement>(
    "td, th, [role='gridcell'], [role='cell']"
  )
  if (startCell && startCell === endCell) {
    const row = startCell.closest<HTMLElement>("tr, [role='row']")
    return row ?? startCell
  }

  const startRow = start.closest<HTMLElement>("tr, [role='row']")
  const endRow = end.closest<HTMLElement>("tr, [role='row']")
  if (startRow && startRow === endRow) return startRow

  const findLabelContainer = (element: Element): HTMLElement | null => {
    let candidate = element.parentElement
    for (let depth = 0; candidate && depth < 6; depth += 1) {
      const labels = Array.from(candidate.querySelectorAll("label")).filter(
        (label) =>
          !label.hidden &&
          label.getAttribute("aria-hidden") !== "true" &&
          cleanText(label.textContent)
      )
      if (
        labels.length === 1 &&
        cleanText(candidate.textContent).length <= 2_000
      ) {
        return candidate
      }
      candidate = candidate.parentElement
    }
    return null
  }

  const startLabelContainer = findLabelContainer(start)
  const endLabelContainer = findLabelContainer(end)
  return startLabelContainer && startLabelContainer === endLabelContainer
    ? startLabelContainer
    : null
}

export type SmartSelectionSnapshot = {
  text: string
  visual: VisualSelectionSnapshot | null
  markedResult: SmartFormatResult | null
  tableResult: SmartFormatResult | null
  contextualResult: SmartFormatResult | null
  fallbackResult: SmartFormatResult | null
}

const isExplicitContextLabel = (
  element: HTMLElement,
  text: string
): boolean => {
  if (element.matches("label, dt, [data-field-label]")) return true
  if (/[:：]\s*$/.test(text)) return true
  const marker = `${element.id} ${element.className} ${element.getAttribute("data-testid") ?? ""}`
  return /(?:^|[-_\s])(label|field-name|key|term)(?:$|[-_\s])/i.test(marker)
}

const contextualLabelForSelection = (
  selection: Selection,
  visual: VisualSelectionSnapshot
): string | null => {
  if (selection.rangeCount === 0) return null
  const range = selection.getRangeAt(0)
  const start = elementFromNode(range.startContainer)
  const end = elementFromNode(range.endContainer)
  if (!(start instanceof HTMLElement) || !(end instanceof HTMLElement)) {
    return null
  }

  const document = start.ownerDocument
  const selectedRects = visual.tokens
    .map((token) => token.rect)
    .filter((rect): rect is NonNullable<typeof rect> => !!rect)
  const selectedBounds = selectedRects.length
    ? {
        top: Math.min(...selectedRects.map((rect) => rect.top)),
        right: Math.max(...selectedRects.map((rect) => rect.right)),
        bottom: Math.max(...selectedRects.map((rect) => rect.bottom)),
        left: Math.min(...selectedRects.map((rect) => rect.left))
      }
    : null
  const isNearby = (candidate: HTMLElement): boolean => {
    if (!selectedBounds) return false
    const rect = candidate.getBoundingClientRect()
    if (rect.width <= 0 || rect.height <= 0) return false
    const verticalOverlap = Math.max(
      0,
      Math.min(rect.bottom, selectedBounds.bottom) -
        Math.max(rect.top, selectedBounds.top)
    )
    const horizontalOverlap = Math.max(
      0,
      Math.min(rect.right, selectedBounds.right) -
        Math.max(rect.left, selectedBounds.left)
    )
    const sameRow = verticalOverlap > 0 && rect.left <= selectedBounds.left + 4
    const above =
      rect.bottom <= selectedBounds.top + 2 &&
      selectedBounds.top - rect.bottom <= 96 &&
      (horizontalOverlap > 0 || Math.abs(rect.left - selectedBounds.left) <= 16)
    return sameRow || above
  }
  const labelledElement = start.closest<HTMLElement>("[aria-labelledby]")
  if (labelledElement?.contains(end)) {
    const labels = (labelledElement.getAttribute("aria-labelledby") ?? "")
      .split(/\s+/)
      .map((id) => document.getElementById(id))
      .filter(
        (element): element is HTMLElement => element instanceof HTMLElement
      )
      .map(readRenderedElementText)
      .filter((text) => isLikelyLabel(text))
    if (labels.length > 0) return labels.join(" ")
  }

  const describedValue = start.closest<HTMLElement>("[id]")
  if (describedValue?.contains(end)) {
    const id = describedValue.id
    const label = Array.from(
      document.querySelectorAll<HTMLLabelElement>("label")
    ).find((candidate) => candidate.htmlFor === id)
    const labelText = label ? readRenderedElementText(label) : ""
    if (labelText && isLikelyLabel(labelText)) return labelText
  }

  const description = start.closest<HTMLElement>("dd")
  if (description?.contains(end)) {
    const term = description.previousElementSibling
    if (term instanceof HTMLElement && term.matches("dt")) {
      const text = readRenderedElementText(term)
      if (isLikelyLabel(text)) return text
    }
  }

  let container: HTMLElement | null = start
  for (let depth = 0; container && depth < 5; depth += 1) {
    if (!container.contains(end)) {
      container = container.parentElement
      continue
    }

    const labels = Array.from(
      container.querySelectorAll<HTMLElement>(
        "label, dt, [data-field-label], [class*='field-label'], [class~='label']"
      )
    ).filter(
      (candidate) =>
        !candidate.contains(start) &&
        !candidate.contains(end) &&
        isNearby(candidate)
    )
    if (labels.length === 1) {
      const text = readRenderedElementText(labels[0])
      if (text && isLikelyLabel(text)) return text
    }

    const previous = container.previousElementSibling
    if (previous instanceof HTMLElement) {
      const text = readRenderedElementText(previous)
      if (
        text &&
        isLikelyLabel(text) &&
        isExplicitContextLabel(previous, text) &&
        isNearby(previous)
      ) {
        return text
      }
    }
    container = container.parentElement
  }

  return null
}

const formatContextualSelection = (
  selection: Selection,
  visual: VisualSelectionSnapshot | null
): SmartFormatResult | null => {
  if (!visual?.geometryAvailable || visual.tokens.length === 0) return null
  const key = contextualLabelForSelection(selection, visual)
  const value = visualSelectionText(visual)
  if (
    !key ||
    !value ||
    normalizeLabel(key).toLowerCase() === value.toLowerCase()
  ) {
    return null
  }
  return {
    kind: "visual-key-value",
    score: 96,
    text: formatKeyValues([[key, value]])
  }
}

export const captureSmartSelection = (
  selection: Selection
): SmartSelectionSnapshot | null => {
  if (!selection || selection.rangeCount === 0) return null
  const visual = captureVisualSelection(selection)
  const markedResult = formatMarkedSelection(selection)
  const tableResult = formatSelectedTable(selection)
  const contextualResult = formatContextualSelection(selection, visual)
  const contextualHeaders = readContextualHeaders(selection)
  const atomicContainer = findAtomicSelectionContainer(selection)
  let fallbackResult: SmartFormatResult | null = null
  if (!visual?.geometryAvailable && atomicContainer) {
    fallbackResult = formatSmartContainer(atomicContainer, contextualHeaders)
  }

  if (!visual?.geometryAvailable && !fallbackResult) {
    const range = selection.getRangeAt(0)
    const wrapper = range.startContainer.ownerDocument.createElement("div")
    wrapper.appendChild(range.cloneContents())
    fallbackResult = formatSmartContainer(wrapper, contextualHeaders)
  }

  return {
    text: selection.toString(),
    visual,
    markedResult,
    tableResult,
    contextualResult,
    fallbackResult
  }
}

const safeTextCandidate = (text: string): SmartFormatResult | null => {
  const value = cleanTextPreservingLines(text)
  if (!value) return null
  const candidates: SmartFormatResult[] = []
  const json = tryJson(value)
  if (json) candidates.push({ kind: "json", score: 100, text: json })
  const partialJson = tryPartialJson(text)
  if (partialJson) {
    candidates.push({ kind: "partial-json", score: 96, text: partialJson })
  }
  const delimited = extractDelimitedCandidate(value)
  if (delimited) candidates.push(delimited)
  const structured = extractTextCandidate(value)
  if (structured) candidates.push(structured)
  return (
    candidates.sort(
      (left, right) =>
        right.score - left.score || right.text.length - left.text.length
    )[0] ?? null
  )
}

export const formatSmartSelectionSnapshot = (
  snapshot: SmartSelectionSnapshot
): SmartFormatResult | null => {
  // Explicit product fields and real tables have semantics that geometry alone
  // cannot improve, and are captured before the page can mutate the selection.
  if (snapshot.markedResult) return snapshot.markedResult
  if (snapshot.tableResult) return snapshot.tableResult

  if (snapshot.visual) {
    const visualCandidate = buildVisualCandidate(snapshot.visual)
    if (visualCandidate) {
      return {
        kind: "visual-key-value",
        score: visualCandidate.score,
        text: formatKeyValues(visualCandidate.pairs)
      }
    }

    if (snapshot.contextualResult) return snapshot.contextualResult

    if (snapshot.visual.geometryAvailable) {
      // Once rendered geometry is available, never fall back to ancestor DOM
      // content: it may contain tooltips, hidden panels or internal state.
      return safeTextCandidate(visualSelectionText(snapshot.visual))
    }
  }

  // Headless DOMs and older engines do not expose useful text rectangles.
  // Preserve the semantic parser as a compatibility fallback in that case.
  return snapshot.fallbackResult
}

export const formatSmartSelection = (
  selection: Selection
): SmartFormatResult | null => {
  const snapshot = captureSmartSelection(selection)
  return snapshot ? formatSmartSelectionSnapshot(snapshot) : null
}
