export type SmartFormatKind =
  | "json"
  | "semantic-table"
  | "semantic-key-value"
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

const directCells = (row: Element): HTMLElement[] =>
  Array.from(row.children).filter(
    (child): child is HTMLElement =>
      child instanceof HTMLElement &&
      (child.matches("th, td") ||
        ["columnheader", "rowheader", "gridcell", "cell"].includes(
          child.getAttribute("role") ?? ""
        ))
  )

const getCellIndex = (cell: HTMLElement, fallback: number): number => {
  const raw = Number(cell.getAttribute("aria-colindex"))
  return Number.isInteger(raw) && raw > 0 ? raw - 1 : fallback
}

const readRow = (
  row: Element
): { cells: string[]; headerCells: boolean } | null => {
  const cells = directCells(row)
  if (cells.length === 0) return null

  const indexed = cells.map((cell, index) => ({
    index: getCellIndex(cell, index),
    text: cleanText(cell.textContent),
    span: Math.max(1, Number(cell.getAttribute("colspan")) || 1)
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

const inferHeadersFromCells = (
  rows: Element[],
  columnCount: number
): string[] | undefined => {
  const headers = Array.from({ length: columnCount }, () => "")
  for (const row of rows) {
    directCells(row).forEach((cell, fallbackIndex) => {
      const index = getCellIndex(cell, fallbackIndex)
      if (headers[index]) return
      const label =
        cell.getAttribute("data-column-name") ??
        cell.getAttribute("data-field-name") ??
        cell.getAttribute("aria-label")
      if (label && isLikelyLabel(label)) headers[index] = normalizeLabel(label)
    })
  }
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
      values[getCellIndex(cell, index)] = cleanText(cell.textContent)
    })
    matrices.push({
      rows: [values],
      headers:
        contextualHeaders.length === width ? contextualHeaders : undefined,
      semanticHeaders: contextualHeaders.length === width,
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
    const explicitHeader = parsed.findIndex((row) => row.headerCells)
    const rows = parsed
      .filter((_, index) => index !== explicitHeader)
      .map((row) => row.cells)
    if (rows.length > 0) {
      const count = Math.max(...rows.map((row) => row.length))
      matrices.push({
        rows,
        headers:
          explicitHeader >= 0
            ? parsed[explicitHeader].cells
            : contextualHeaders.length === count
              ? contextualHeaders
              : undefined,
        semanticHeaders:
          explicitHeader >= 0 || contextualHeaders.length === count,
        source: orphanRows.some((row) => row.matches("tr")) ? "table" : "grid"
      })
    }
  }

  const tableRoots: Element[] = Array.from(container.querySelectorAll("table"))
  if (container.matches("table")) tableRoots.unshift(container)

  tableRoots.forEach((table) => {
    const rowElements = Array.from(table.querySelectorAll("tr"))
    const parsed = rowElements
      .map(readRow)
      .filter((row): row is NonNullable<typeof row> => !!row)
    if (parsed.length === 0) return
    const explicitHeader = parsed.findIndex((row) => row.headerCells)
    const headers =
      explicitHeader >= 0 ? parsed[explicitHeader].cells : undefined
    const rows = parsed
      .filter((_, index) => index !== explicitHeader)
      .map((row) => row.cells)
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
        explicitHeader >= 0 || contextualHeaders.length === count,
      source: "table"
    })
  })

  const gridRoots = Array.from(
    container.querySelectorAll<HTMLElement>("[role='grid'], [role='table']")
  )
  if (container.matches("[role='grid'], [role='table']"))
    gridRoots.unshift(container)

  gridRoots.forEach((grid) => {
    const rowElements = Array.from(grid.querySelectorAll("[role='row']"))
    const parsed = rowElements
      .map(readRow)
      .filter((row): row is NonNullable<typeof row> => !!row)
    if (parsed.length === 0) return
    const explicitHeader = parsed.findIndex((row) => row.headerCells)
    const headers =
      explicitHeader >= 0 ? parsed[explicitHeader].cells : undefined
    const rows = parsed
      .filter((_, index) => index !== explicitHeader)
      .map((row) => row.cells)
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
        explicitHeader >= 0 || contextualHeaders.length === count,
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
    score: matrix.semanticHeaders ? 96 : matrix.source === "table" ? 91 : 89,
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
    addPair(term.textContent, value.textContent)
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
        .map((child) => cleanText(child.textContent))
        .filter(Boolean)
      if (segments.length < 2 || !isLikelyLabel(segments[0])) return
      const value = segments.slice(1).join(" ")
      addPair(segments[0], value)
    })

  container.querySelectorAll<HTMLElement>("strong").forEach((label) => {
    const keyText = cleanText(label.textContent)
    if (!/[:：]\s*$/.test(keyText) || !isLikelyLabel(keyText)) return
    const value = label.nextElementSibling
    if (value) addPair(keyText, value.textContent)
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
      score: Math.min(99, 86 + semanticPairs.length * 2),
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

  const headerRow = Array.from(
    startRoot.querySelectorAll("tr, [role='row']")
  ).find((row) => {
    const cells = directCells(row)
    return (
      cells.length > 0 &&
      cells.every((cell) => cell.matches("th, [role='columnheader']"))
    )
  })
  return headerRow
    ? directCells(headerRow).map((cell) => cleanText(cell.textContent))
    : []
}

const findAtomicSelectionContainer = (
  selection: Selection
): HTMLElement | null => {
  if (selection.rangeCount === 0) return null
  const range = selection.getRangeAt(0)
  const start = elementFromNode(range.startContainer)
  const end = elementFromNode(range.endContainer)
  if (!start || !end) return null

  const dataSelector =
    "[data-field-name], [data-field], [context-data-property], [data-column-name]"
  const startData = start.closest<HTMLElement>(dataSelector)
  const endData = end.closest<HTMLElement>(dataSelector)
  if (startData && startData === endData) {
    const attribute = [
      "data-field-name",
      "data-field",
      "context-data-property",
      "data-column-name"
    ].find((name) => startData.hasAttribute(name))
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

export const formatSmartSelection = (
  selection: Selection
): SmartFormatResult | null => {
  if (!selection || selection.rangeCount === 0) return null
  const contextualHeaders = readContextualHeaders(selection)
  const atomicContainer = findAtomicSelectionContainer(selection)
  if (atomicContainer) {
    const contextualResult = formatSmartContainer(
      atomicContainer,
      contextualHeaders
    )
    if (contextualResult) return contextualResult
  }
  const range = selection.getRangeAt(0)
  const wrapper = range.startContainer.ownerDocument.createElement("div")
  wrapper.appendChild(range.cloneContents())
  return formatSmartContainer(wrapper, contextualHeaders)
}
