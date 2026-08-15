import type { ResolvedServicePage } from "./servicePageAdapters"

export type ServiceIntelField = {
  label: string
  value: string
}

const MAX_FIELDS = 48
const MAX_FIELD_LENGTH = 600
const MAX_REPORT_LENGTH = 9_000
const EXCLUDED_SELECTOR = [
  "nav",
  "header",
  "footer",
  "aside",
  "script",
  "style",
  "noscript",
  "template",
  "[role='dialog']",
  "[aria-hidden='true']",
  "[data-socx-service-copy]"
].join(",")

const NOISE_LINES = new Set([
  "copy",
  "copy link",
  "learn more",
  "show more",
  "sign in",
  "log in",
  "login",
  "home",
  "menu",
  "search",
  "close",
  "cancel",
  "privacy",
  "terms of use"
])

const INTERSTITIAL_PATTERN =
  /(?:just a moment|checking your browser|verify you are human|confirm that you are not a robot|security check)/i

export const normalizeServiceText = (
  value: string | null | undefined
): string =>
  (value ?? "")
    .replace(/\u00a0/g, " ")
    .replace(/[ \t]+/g, " ")
    .trim()

export const isServicePageReady = (
  rootDocument: Document = document
): boolean => {
  const pageSignal = `${rootDocument.title}\n${rootDocument.body?.innerText?.slice(0, 500) ?? ""}`
  return !INTERSTITIAL_PATTERN.test(pageSignal)
}

const compactValue = (value: string): string =>
  normalizeServiceText(value).slice(0, MAX_FIELD_LENGTH)

const isUsefulText = (value: string): boolean => {
  const normalized = normalizeServiceText(value)
  return (
    normalized.length >= 2 &&
    normalized.length <= MAX_FIELD_LENGTH &&
    !NOISE_LINES.has(normalized.toLowerCase())
  )
}

const isExcluded = (element: Element): boolean =>
  Boolean(
    element.matches(EXCLUDED_SELECTOR) || element.closest(EXCLUDED_SELECTOR)
  )

const collectShadowRoots = (
  root: Document | ShadowRoot
): Array<Document | ShadowRoot> => {
  const roots: Array<Document | ShadowRoot> = [root]
  for (let index = 0; index < roots.length && roots.length < 100; index += 1) {
    roots[index].querySelectorAll("*").forEach((element) => {
      if (element.shadowRoot && !roots.includes(element.shadowRoot)) {
        roots.push(element.shadowRoot)
      }
    })
  }
  return roots
}

const queryAllDeep = <T extends Element>(
  roots: Array<Document | ShadowRoot>,
  selector: string
): T[] =>
  roots.flatMap((root) => Array.from(root.querySelectorAll<T>(selector)))

const readableText = (element: Element): string => {
  const htmlElement = element as HTMLElement
  return normalizeServiceText(htmlElement.innerText || htmlElement.textContent)
}

const selectReportRoot = (
  roots: Array<Document | ShadowRoot>,
  selectors: string[] = []
): Element => {
  const candidates = queryAllDeep<Element>(
    roots,
    [
      ...selectors,
      "main",
      "[role='main']",
      "article",
      "#content",
      ".content"
    ].join(",")
  ).filter((element) => !isExcluded(element))

  return (
    candidates.sort(
      (left, right) => readableText(right).length - readableText(left).length
    )[0] ??
    document.body ??
    document.documentElement
  )
}

const createFieldCollector = () => {
  const fields: ServiceIntelField[] = []
  const seen = new Set<string>()
  let reportLength = 0

  const add = (label: string, value: string) => {
    if (fields.length >= MAX_FIELDS || reportLength >= MAX_REPORT_LENGTH) return
    const normalizedLabel = normalizeServiceText(label).replace(/[:\s]+$/, "")
    const normalizedValue = compactValue(value)
    if (!isUsefulText(normalizedLabel) || !isUsefulText(normalizedValue)) return
    if (normalizedLabel === normalizedValue) return

    const key = `${normalizedLabel.toLowerCase()}\u0000${normalizedValue.toLowerCase()}`
    if (seen.has(key)) return
    seen.add(key)
    reportLength += normalizedLabel.length + normalizedValue.length
    fields.push({ label: normalizedLabel, value: normalizedValue })
  }

  return { fields, add }
}

const flattenJson = (
  value: unknown,
  add: (label: string, value: string) => void,
  path = "Result",
  depth = 0
): void => {
  if (depth > 3 || value === null || value === undefined) return
  if (typeof value !== "object") {
    add(path, String(value))
    return
  }

  if (Array.isArray(value)) {
    value
      .slice(0, 8)
      .forEach((item, index) =>
        flattenJson(item, add, `${path} ${index + 1}`, depth + 1)
      )
    return
  }

  Object.entries(value as Record<string, unknown>)
    .slice(0, 30)
    .forEach(([key, item]) =>
      flattenJson(
        item,
        add,
        path === "Result" ? key : `${path} / ${key}`,
        depth + 1
      )
    )
}

const extractJsonDocument = (
  root: Element,
  add: (label: string, value: string) => void
): boolean => {
  const raw = readableText(root)
  if (!(raw.startsWith("{") || raw.startsWith("["))) return false
  try {
    flattenJson(JSON.parse(raw), add)
    return true
  } catch {
    return false
  }
}

const extractTables = (
  roots: Array<Document | ShadowRoot>,
  reportRoot: Element,
  add: (label: string, value: string) => void
): void => {
  const tables = queryAllDeep<HTMLTableElement>(roots, "table")
    .filter(
      (table) => reportRoot.contains(table) || table.getRootNode() !== document
    )
    .filter((table) => !isExcluded(table))
    .slice(0, 8)

  tables.forEach((table, tableIndex) => {
    const rows = Array.from(table.querySelectorAll("tr")).slice(0, 24)
    const headers = Array.from(rows[0]?.querySelectorAll("th") ?? []).map(
      readableText
    )

    rows.forEach((row, rowIndex) => {
      const cells = Array.from(row.querySelectorAll("th,td"))
        .map(readableText)
        .filter(Boolean)
      if (
        cells.length < 2 ||
        (rowIndex === 0 && headers.length === cells.length)
      )
        return

      if (cells.length === 2 && headers.length === 0) {
        add(cells[0], cells[1])
        return
      }

      const value = cells
        .map((cell, cellIndex) =>
          headers[cellIndex] ? `${headers[cellIndex]}=${cell}` : cell
        )
        .join(" | ")
      add(`Table ${tableIndex + 1}, row ${rowIndex + 1}`, value)
    })
  })
}

const extractDefinitionLists = (
  roots: Array<Document | ShadowRoot>,
  reportRoot: Element,
  add: (label: string, value: string) => void
): void => {
  queryAllDeep<HTMLElement>(roots, "dt")
    .filter(
      (term) => reportRoot.contains(term) || term.getRootNode() !== document
    )
    .filter((term) => !isExcluded(term))
    .slice(0, 40)
    .forEach((term) => {
      const description = term.nextElementSibling
      if (description?.matches("dd"))
        add(readableText(term), readableText(description))
    })
}

const extractTextPairs = (
  reportRoot: Element,
  add: (label: string, value: string) => void
): void => {
  const rawText =
    (reportRoot as HTMLElement).innerText || reportRoot.textContent || ""
  rawText
    .split(/\r?\n/)
    .map(normalizeServiceText)
    .filter(Boolean)
    .slice(0, 300)
    .forEach((line) => {
      const match = line.match(/^([^:]{2,64}):\s+(.{1,600})$/)
      if (match) add(match[1], match[2])
    })
}

const extractHeadings = (
  roots: Array<Document | ShadowRoot>,
  reportRoot: Element,
  add: (label: string, value: string) => void
): void => {
  queryAllDeep<HTMLElement>(roots, "h1,h2,h3,h4")
    .filter(
      (heading) =>
        reportRoot.contains(heading) || heading.getRootNode() !== document
    )
    .filter((heading) => !isExcluded(heading))
    .slice(0, 20)
    .forEach((heading) => {
      const value = heading.nextElementSibling
        ? readableText(heading.nextElementSibling).slice(0, MAX_FIELD_LENGTH)
        : ""
      if (value) add(readableText(heading), value)
    })
}

const extractSummaryLines = (
  reportRoot: Element,
  add: (label: string, value: string) => void,
  existingFieldCount: number
): void => {
  if (existingFieldCount >= 8) return
  const rawText =
    (reportRoot as HTMLElement).innerText || reportRoot.textContent || ""
  let summaryIndex = 0
  rawText
    .split(/\r?\n/)
    .map(normalizeServiceText)
    .filter((line) => isUsefulText(line) && line.length >= 12)
    .slice(0, 16)
    .forEach((line) => {
      summaryIndex += 1
      add(`Summary ${summaryIndex}`, line)
    })
}

const extractAbuseIpdb = (
  reportRoot: Element,
  add: (label: string, value: string) => void
): void => {
  const text = (selector: string): string =>
    readableText(
      reportRoot.querySelector(selector) ?? document.createElement("span")
    )

  add("IP", text("h3 > b"))
  add("Reports", text("p > b"))
  add("Abuse confidence", text(".progress-bar > span"))
  reportRoot.querySelectorAll("table tr").forEach((row) => {
    const label = readableText(
      row.querySelector("th") ?? document.createElement("span")
    )
    const valueCell = row.querySelector("td")
    if (!label || !valueCell) return
    const clone = valueCell.cloneNode(true) as HTMLElement
    clone.querySelectorAll(".flag-emoji").forEach((node) => node.remove())
    add(label, readableText(clone))
  })
}

export const extractServicePageFields = (
  page: ResolvedServicePage,
  rootDocument: Document = document
): ServiceIntelField[] => {
  const roots = collectShadowRoots(rootDocument)
  const reportRoot = selectReportRoot(roots, page.adapter.rootSelectors)
  const { fields, add } = createFieldCollector()

  if (page.adapter.id === "AbuseIPDB") extractAbuseIpdb(reportRoot, add)
  if (!extractJsonDocument(reportRoot, add)) {
    extractTables(roots, reportRoot, add)
    extractDefinitionLists(roots, reportRoot, add)
    extractTextPairs(reportRoot, add)
    extractHeadings(roots, reportRoot, add)
    extractSummaryLines(reportRoot, add, fields.length)
  }

  if (fields.length === 0 && rootDocument.title)
    add("Page title", rootDocument.title)
  return fields
}

const cleanSourceUrl = (value: string): string => {
  try {
    const url = new URL(value)
    Array.from(url.searchParams.keys()).forEach((key) => {
      if (key.startsWith("utm_") || key.startsWith("__cf_") || key === "ref") {
        url.searchParams.delete(key)
      }
    })
    return url.toString()
  } catch {
    return value
  }
}

export const formatServicePageReport = ({
  page,
  fields,
  sourceUrl,
  capturedAt = new Date()
}: {
  page: ResolvedServicePage
  fields: ServiceIntelField[]
  sourceUrl: string
  capturedAt?: Date
}): string => {
  const lines = [
    "SOCx IOC report",
    `- Service: ${page.adapter.label}`,
    `- IOC: ${page.ioc}`,
    `- Source: ${cleanSourceUrl(sourceUrl)}`,
    `- Captured: ${capturedAt.toISOString()}`
  ]

  fields.forEach(({ label, value }) => {
    lines.push(`- Detail: ${label} — ${value}`)
  })
  return lines.join("\n")
}
